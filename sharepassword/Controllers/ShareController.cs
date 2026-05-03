using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using System.Security.Claims;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

public class ShareController : Controller
{
    private readonly IShareStore _shareStore;
    private readonly IAccessCodeService _accessCodeService;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly IAuditLogger _auditLogger;
    private readonly IApplicationTime _applicationTime;
    private readonly IUsageMetricsService _usageMetricsService;
    private readonly INotificationEmailService _notificationEmailService;
    private readonly ISystemConfigurationService _systemConfigurationService;
    private readonly OidcAuthOptions _oidcAuthOptions;

    public ShareController(
        IShareStore shareStore,
        IAccessCodeService accessCodeService,
        IPasswordCryptoService passwordCryptoService,
        IAuditLogger auditLogger,
        IApplicationTime applicationTime,
        IUsageMetricsService usageMetricsService,
        INotificationEmailService notificationEmailService,
        ISystemConfigurationService systemConfigurationService,
        IOptions<OidcAuthOptions> oidcAuthOptions)
    {
        _shareStore = shareStore;
        _accessCodeService = accessCodeService;
        _passwordCryptoService = passwordCryptoService;
        _auditLogger = auditLogger;
        _applicationTime = applicationTime;
        _usageMetricsService = usageMetricsService;
        _notificationEmailService = notificationEmailService;
        _systemConfigurationService = systemConfigurationService;
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

        PasswordShare? share;
        try
        {
            share = await _shareStore.GetShareByTokenAsync(token);
        }
        catch (DatabaseOperationException exception)
        {
            var unavailableModel = new ShareAccessViewModel { Token = token };
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(unavailableModel);
        }

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
                    RedirectUri = ApplicationPathHelper.BuildAppPath(Request.PathBase, Url.Action(nameof(Access), new { token }) ?? "/")
                }, OpenIdConnectDefaults.AuthenticationScheme);
            }

            var oidcEmail = GetAuthenticatedEmail();
            if (string.IsNullOrWhiteSpace(oidcEmail))
            {
                await _auditLogger.LogAsync("oidc-user", "unknown", "share.access", false, details: "Microsoft Entra ID-authenticated user has no usable email claim.");
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
        model.Code = (model.Code ?? string.Empty).Trim();

        if (!IsValidToken(model.Token))
        {
            return BadRequest();
        }

        PasswordShare? share;
        try
        {
            share = await _shareStore.GetShareByTokenAsync(model.Token);
        }
        catch (DatabaseOperationException exception)
        {
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

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
                    RedirectUri = ApplicationPathHelper.BuildAppPath(Request.PathBase, Url.Action(nameof(Access), new { token = model.Token }) ?? "/")
                }, OpenIdConnectDefaults.AuthenticationScheme);
            }

            var oidcEmail = GetAuthenticatedEmail();
            if (string.IsNullOrWhiteSpace(oidcEmail))
            {
                await _auditLogger.LogAsync("oidc-user", "unknown", "share.access", false, details: "Microsoft Entra ID-authenticated user has no usable email claim.");
                ModelState.AddModelError(string.Empty, "Unable to resolve your Microsoft Entra ID email from token claims.");
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

        if (share is null)
        {
            await _auditLogger.LogAsync("external-user", email, "share.access", false, details: "Unknown token.");
            ModelState.AddModelError(string.Empty, "Invalid link or access details.");
            return View(model);
        }

        if (share.ExpiresAtUtc <= _applicationTime.UtcNow)
        {
            try
            {
                await _shareStore.DeleteShareAsync(share.Id);
            }
            catch (DatabaseOperationException exception)
            {
                ModelState.AddModelError(string.Empty, exception.UserMessage);
                return View(model);
            }

            await _auditLogger.LogAsync("external-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), "Share expired.");
            ModelState.AddModelError(string.Empty, "This password share has expired.");
            return View(model);
        }

        var pausedResult = await EnforceShareAccessPauseAsync(share, model, email);
        if (pausedResult is not null)
        {
            return pausedResult;
        }

        if (!string.Equals(share.RecipientEmail, email, StringComparison.OrdinalIgnoreCase))
        {
            return await RecordFailedShareAccessAsync(share, model, email, "Email mismatch.");
        }

        if (!AccessCodeFormat.IsValid(model.Code))
        {
            ModelState.AddModelError(nameof(model.Code), AccessCodeFormat.InvalidFormatErrorMessage);
            return await RecordFailedShareAccessAsync(share, model, email, "Invalid access code format.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (!_accessCodeService.Verify(model.Code, share.AccessCodeHash))
        {
            return await RecordFailedShareAccessAsync(share, model, email, "Access code mismatch.");
        }

        share.LastAccessedAtUtc = _applicationTime.UtcNow;
        share.FailedAccessAttempts = 0;
        share.AccessPausedUntilUtc = null;
        try
        {
            await _shareStore.UpsertShareAsync(share);
        }
        catch (DatabaseOperationException exception)
        {
            await _auditLogger.LogAsync("external-user", email, "share.access", false, "PasswordShare", share.Id.ToString(), exception.DiagnosticMessage);
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

        await _auditLogger.LogAsync("external-user", email, "share.access", true, "PasswordShare", share.Id.ToString());
        await _usageMetricsService.RecordAsync(DbUsageMetricsService.ShareAccessedKey, "external-user", email, relatedId: share.Id.ToString(), details: "Share accessed.");

        try
        {
            await _notificationEmailService.NotifyShareAccessedAsync(share, email);
        }
        catch (Exception ex)
        {
            await _auditLogger.LogAsync("system", "mail-service", "mail.share-access.failed", false, "PasswordShare", share.Id.ToString(), ex.GetBaseException().Message);
        }

        var secretEncryptionMode = SecretEncryptionModes.Normalize(share.SecretEncryptionMode);
        var secretPayload = SecretEncryptionModes.IsClientEncrypted(secretEncryptionMode)
            ? share.EncryptedPassword
            : _passwordCryptoService.Decrypt(share.EncryptedPassword);

        return View("Credential", new ShareCredentialViewModel
        {
            ShareId = share.Id,
            RecipientEmail = email,
            Username = share.SharedUsername,
            Password = secretPayload,
            SecretEncryptionMode = secretEncryptionMode,
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
        try
        {
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
        catch (DatabaseOperationException exception)
        {
            await _auditLogger.LogAsync("external-user", normalizedEmail, "share.delete-after-retrieve", false, "PasswordShare", shareId.ToString(), exception.DiagnosticMessage);
            return StatusCode(StatusCodes.Status503ServiceUnavailable, exception.UserMessage);
        }
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

    private async Task<IActionResult?> EnforceShareAccessPauseAsync(PasswordShare share, ShareAccessViewModel model, string email)
    {
        if (share.AccessPausedUntilUtc is not { } pausedUntilUtc)
        {
            return null;
        }

        var utcNow = _applicationTime.UtcNow;
        if (pausedUntilUtc > utcNow)
        {
            await _auditLogger.LogAsync("external-user", GetAuditIdentifier(email), "share.access", false, "PasswordShare", share.Id.ToString(), "Share access paused after failed attempts.");
            ModelState.AddModelError(string.Empty, BuildPausedMessage(pausedUntilUtc, utcNow));
            return View(model);
        }

        share.FailedAccessAttempts = 0;
        share.AccessPausedUntilUtc = null;
        try
        {
            await _shareStore.UpsertShareAsync(share);
        }
        catch (DatabaseOperationException exception)
        {
            await _auditLogger.LogAsync("external-user", GetAuditIdentifier(email), "share.access", false, "PasswordShare", share.Id.ToString(), exception.DiagnosticMessage);
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

        return null;
    }

    private async Task<IActionResult> RecordFailedShareAccessAsync(PasswordShare share, ShareAccessViewModel model, string email, string details)
    {
        SystemConfiguration configuration;
        try
        {
            configuration = await _systemConfigurationService.GetConfigurationAsync();
        }
        catch (DatabaseOperationException exception)
        {
            await _auditLogger.LogAsync("external-user", GetAuditIdentifier(email), "share.access", false, "PasswordShare", share.Id.ToString(), exception.DiagnosticMessage);
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

        var failedAttemptLimit = Math.Max(1, configuration.ShareAccessFailedAttemptLimit);
        var pauseMinutes = Math.Max(1, configuration.ShareAccessPauseMinutes);
        var utcNow = _applicationTime.UtcNow;

        share.FailedAccessAttempts = Math.Max(0, share.FailedAccessAttempts) + 1;
        if (share.FailedAccessAttempts >= failedAttemptLimit)
        {
            share.AccessPausedUntilUtc = utcNow.AddMinutes(pauseMinutes);
        }

        try
        {
            await _shareStore.UpsertShareAsync(share);
        }
        catch (DatabaseOperationException exception)
        {
            await _auditLogger.LogAsync("external-user", GetAuditIdentifier(email), "share.access", false, "PasswordShare", share.Id.ToString(), exception.DiagnosticMessage);
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

        var auditDetails = share.AccessPausedUntilUtc is null
            ? details
            : $"{details} Share access paused after {share.FailedAccessAttempts} failed attempts.";
        await _auditLogger.LogAsync("external-user", GetAuditIdentifier(email), "share.access", false, "PasswordShare", share.Id.ToString(), auditDetails);

        if (share.AccessPausedUntilUtc is { } pausedUntilUtc)
        {
            ModelState.AddModelError(string.Empty, BuildPausedMessage(pausedUntilUtc, utcNow));
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid link or access details.");
        }

        return View(model);
    }

    private static string BuildPausedMessage(DateTime pausedUntilUtc, DateTime utcNow)
    {
        var remainingMinutes = Math.Max(1, (int)Math.Ceiling((pausedUntilUtc - utcNow).TotalMinutes));
        return $"Too many failed attempts for this share. Try again in {remainingMinutes} minute{(remainingMinutes == 1 ? string.Empty : "s")}.";
    }

    private static string GetAuditIdentifier(string email)
    {
        return string.IsNullOrWhiteSpace(email) ? "unknown" : email;
    }

    private static bool IsValidToken(string token)
    {
        return token.Length == 32 && token.All(Uri.IsHexDigit);
    }
}
