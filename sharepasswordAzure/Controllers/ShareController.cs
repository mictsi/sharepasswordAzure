using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

public class ShareController : Controller
{
    private const int AccessCodeLength = 8;

    private readonly IShareStore _shareStore;
    private readonly IAccessCodeService _accessCodeService;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly IAuditLogger _auditLogger;
    private readonly OidcAuthOptions _oidcAuthOptions;

    public ShareController(
        IShareStore shareStore,
        IAccessCodeService accessCodeService,
        IPasswordCryptoService passwordCryptoService,
        IAuditLogger auditLogger,
        IOptions<OidcAuthOptions> oidcAuthOptions)
    {
        _shareStore = shareStore;
        _accessCodeService = accessCodeService;
        _passwordCryptoService = passwordCryptoService;
        _auditLogger = auditLogger;
        _oidcAuthOptions = oidcAuthOptions.Value;
    }

    [HttpGet]
    public async Task<IActionResult> Access(string token)
    {
        token = (token ?? string.Empty).Trim();
        if (!IsValidToken(token))
        {
            return BadRequest();
        }

        var share = await _shareStore.GetShareByTokenAsync(token);
        var model = new ShareAccessViewModel { Token = token, RequireOidcLogin = share?.RequireOidcLogin ?? false };

        if (share?.RequireOidcLogin == true)
        {
            if (!_oidcAuthOptions.Enabled)
            {
                return Forbid();
            }

            if (User.Identity?.IsAuthenticated != true)
            {
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Access), new { token })
                }, OpenIdConnectDefaults.AuthenticationScheme);
            }

            var oidcEmail = GetAuthenticatedEmail();
            if (string.IsNullOrWhiteSpace(oidcEmail))
            {
                await _auditLogger.LogAsync("oidc-user", "unknown", "share.access", false, details: "OIDC-authenticated user has no usable email claim.");
                return Forbid();
            }

            if (share is not null && !string.Equals(share.RecipientEmail, oidcEmail, StringComparison.OrdinalIgnoreCase))
            {
                await _auditLogger.LogAsync("oidc-user", oidcEmail, "share.access", false, "PasswordShare", share.Id.ToString(), "OIDC recipient mismatch.");
                return Forbid();
            }

            model.Email = oidcEmail;
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Access(ShareAccessViewModel model)
    {
        model.Token = (model.Token ?? string.Empty).Trim();
        model.Code = (model.Code ?? string.Empty).Trim().ToUpperInvariant();

        if (!IsValidToken(model.Token))
        {
            return BadRequest();
        }

        if (model.Code.Length != AccessCodeLength || !model.Code.All(char.IsLetterOrDigit))
        {
            ModelState.AddModelError(nameof(model.Code), "Access code format is invalid.");
        }

        var share = await _shareStore.GetShareByTokenAsync(model.Token);
        model.RequireOidcLogin = share?.RequireOidcLogin ?? false;

        var email = (model.Email ?? string.Empty).Trim().ToLowerInvariant();

        if (share?.RequireOidcLogin == true)
        {
            if (!_oidcAuthOptions.Enabled)
            {
                return Forbid();
            }

            if (User.Identity?.IsAuthenticated != true)
            {
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Access), new { token = model.Token })
                }, OpenIdConnectDefaults.AuthenticationScheme);
            }

            var oidcEmail = GetAuthenticatedEmail();
            if (string.IsNullOrWhiteSpace(oidcEmail))
            {
                await _auditLogger.LogAsync("oidc-user", "unknown", "share.access", false, details: "OIDC-authenticated user has no usable email claim.");
                ModelState.AddModelError(string.Empty, "Unable to resolve your Entra ID email from token claims.");
                return View(model);
            }

            model.Email = oidcEmail;
            email = oidcEmail;

            if (share is not null && !string.Equals(share.RecipientEmail, email, StringComparison.OrdinalIgnoreCase))
            {
                await _auditLogger.LogAsync("oidc-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), "OIDC recipient mismatch.");
                return Forbid();
            }
        }
        else if (string.IsNullOrWhiteSpace(email))
        {
            ModelState.AddModelError(nameof(model.Email), "Email address is required.");
            return View(model);
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (share is null)
        {
            await _auditLogger.LogAsync("external-user", email, "share.access", false, details: "Unknown token.");
            ModelState.AddModelError(string.Empty, "Invalid link or access details.");
            return View(model);
        }

        if (share.ExpiresAtUtc <= DateTime.UtcNow)
        {
            await _shareStore.DeleteShareAsync(share.Id);

            await _auditLogger.LogAsync("external-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), "Share expired.");
            ModelState.AddModelError(string.Empty, "This password share has expired.");
            return View(model);
        }

        if (!string.Equals(share.RecipientEmail, email, StringComparison.OrdinalIgnoreCase))
        {
            await _auditLogger.LogAsync("external-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), "Email mismatch.");
            ModelState.AddModelError(string.Empty, "Invalid link or access details.");
            return View(model);
        }

        if (!_accessCodeService.Verify(model.Code, share.AccessCodeHash))
        {
            await _auditLogger.LogAsync("external-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), "Access code mismatch.");
            ModelState.AddModelError(string.Empty, "Invalid link or access details.");
            return View(model);
        }

        share.LastAccessedAtUtc = DateTime.UtcNow;
        await _shareStore.UpsertShareAsync(share);

        await _auditLogger.LogAsync("external-user", email, "share.access", true, "PasswordShare", share.Id.ToString());

        var decryptedPassword = _passwordCryptoService.Decrypt(share.EncryptedPassword);
        return View("Credential", new ShareCredentialViewModel
        {
            ShareId = share.Id,
            RecipientEmail = email,
            Username = share.SharedUsername,
            Password = decryptedPassword,
            Instructions = share.Instructions,
            ExpiresAtUtc = share.ExpiresAtUtc
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteAfterRetrieve(Guid shareId, string recipientEmail)
    {
        if (shareId == Guid.Empty)
        {
            return BadRequest();
        }

        var normalizedEmail = (recipientEmail ?? string.Empty).Trim().ToLowerInvariant();
        var share = await _shareStore.GetShareByIdAsync(shareId);

        if (share is null)
        {
            await _auditLogger.LogAsync("external-user", normalizedEmail, "share.delete-after-retrieve", false, details: "Share not found.");
            return View("Deleted");
        }

        await _shareStore.DeleteShareAsync(shareId);
        await _auditLogger.LogAsync("external-user", normalizedEmail, "share.delete-after-retrieve", true, "PasswordShare", shareId.ToString());

        return View("Deleted");
    }

    private string GetAuthenticatedEmail()
    {
        return User.FindFirstValue("preferred_username")?.Trim().ToLowerInvariant()
               ?? User.FindFirstValue("email")?.Trim().ToLowerInvariant()
               ?? User.FindFirstValue(ClaimTypes.Email)?.Trim().ToLowerInvariant()
               ?? User.FindFirstValue("upn")?.Trim().ToLowerInvariant()
               ?? User.FindFirstValue("unique_name")?.Trim().ToLowerInvariant()
               ?? string.Empty;
    }

    private static bool IsValidToken(string token)
    {
        return token.Length == 32 && token.All(Uri.IsHexDigit);
    }
}
