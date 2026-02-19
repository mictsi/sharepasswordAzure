using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

[Authorize(Policy = "AdminOnly")]
public class AdminController : Controller
{
    private readonly IShareStore _shareStore;
    private readonly IAuditLogReader _auditLogReader;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly IAccessCodeService _accessCodeService;
    private readonly IAuditLogger _auditLogger;
    private readonly ShareOptions _shareOptions;

    public AdminController(
        IShareStore shareStore,
        IAuditLogReader auditLogReader,
        IPasswordCryptoService passwordCryptoService,
        IAccessCodeService accessCodeService,
        IAuditLogger auditLogger,
        IOptions<ShareOptions> shareOptions)
    {
        _shareStore = shareStore;
        _auditLogReader = auditLogReader;
        _passwordCryptoService = passwordCryptoService;
        _accessCodeService = accessCodeService;
        _auditLogger = auditLogger;
        _shareOptions = shareOptions.Value;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var shares = await _shareStore.GetAllSharesAsync();
        var items = shares
            .OrderByDescending(x => x.CreatedAtUtc)
            .Select(x => new AdminShareListItemViewModel
            {
                Id = x.Id,
                RecipientEmail = x.RecipientEmail,
                SharedUsername = x.SharedUsername,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                IsExpired = x.ExpiresAtUtc <= DateTime.UtcNow
            })
            .ToList();

        return View(items);
    }

    [HttpGet]
    public IActionResult Create()
    {
        return View(new AdminCreateShareViewModel { ExpiryHours = _shareOptions.DefaultExpiryHours });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(AdminCreateShareViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var accessCode = _accessCodeService.GenerateCode();
        var token = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var now = DateTime.UtcNow;

        var share = new PasswordShare
        {
            Id = Guid.NewGuid(),
            RecipientEmail = model.RecipientEmail.Trim().ToLowerInvariant(),
            SharedUsername = model.SharedUsername.Trim(),
            EncryptedPassword = _passwordCryptoService.Encrypt(model.Password),
            AccessCodeHash = _accessCodeService.HashCode(accessCode),
            AccessToken = token,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.AddHours(model.ExpiryHours),
            CreatedBy = User.Identity?.Name ?? "admin"
        };

        await _shareStore.UpsertShareAsync(share);

        await _auditLogger.LogAsync(
            "admin",
            User.Identity?.Name ?? "admin",
            "share.create",
            true,
            targetType: "PasswordShare",
            targetId: share.Id.ToString(),
            details: $"Created share for {share.RecipientEmail} expiring at {share.ExpiresAtUtc:O}");

        var link = Url.Action("Access", "Share", new { token = share.AccessToken }, Request.Scheme) ?? string.Empty;

        return View("Created", new AdminShareCreatedViewModel
        {
            ShareId = share.Id,
            RecipientEmail = share.RecipientEmail,
            ShareLink = link,
            AccessCode = accessCode,
            ExpiresAtUtc = share.ExpiresAtUtc
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(Guid id)
    {
        var share = await _shareStore.GetShareByIdAsync(id);
        if (share is null)
        {
            await _auditLogger.LogAsync("admin", User.Identity?.Name ?? "admin", "share.revoke", false, "PasswordShare", id.ToString(), "Share not found.");
            return NotFound();
        }

        await _shareStore.DeleteShareAsync(id);

        await _auditLogger.LogAsync("admin", User.Identity?.Name ?? "admin", "share.revoke", true, "PasswordShare", id.ToString());
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Audit()
    {
        var logs = await _auditLogReader.GetLatestAsync(500);

        return View(logs);
    }
}
