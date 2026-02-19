using Microsoft.AspNetCore.Mvc;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

public class ShareController : Controller
{
    private readonly IShareStore _shareStore;
    private readonly IAccessCodeService _accessCodeService;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly IAuditLogger _auditLogger;

    public ShareController(
        IShareStore shareStore,
        IAccessCodeService accessCodeService,
        IPasswordCryptoService passwordCryptoService,
        IAuditLogger auditLogger)
    {
        _shareStore = shareStore;
        _accessCodeService = accessCodeService;
        _passwordCryptoService = passwordCryptoService;
        _auditLogger = auditLogger;
    }

    [HttpGet]
    public IActionResult Access(string token)
    {
        return View(new ShareAccessViewModel { Token = token });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Access(ShareAccessViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var email = model.Email.Trim().ToLowerInvariant();
    var share = await _shareStore.GetShareByTokenAsync(model.Token);

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

        if (!_accessCodeService.Verify(model.Code.Trim().ToUpperInvariant(), share.AccessCodeHash))
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
            Username = share.SharedUsername,
            Password = decryptedPassword,
            ExpiresAtUtc = share.ExpiresAtUtc
        });
    }
}
