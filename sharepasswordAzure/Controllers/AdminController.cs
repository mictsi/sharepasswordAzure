using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Azure;
using System.Security.Claims;
using SharePassword.Models;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

[Authorize(Policy = "UserOrAdmin")]
public class AdminController : Controller
{
    private readonly IShareStore _shareStore;
    private readonly IAuditLogReader _auditLogReader;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly IAccessCodeService _accessCodeService;
    private readonly IAuditLogger _auditLogger;
    private readonly ShareOptions _shareOptions;
    private readonly OidcAuthOptions _oidcAuthOptions;
    private readonly string _adminRoleName;

    public AdminController(
        IShareStore shareStore,
        IAuditLogReader auditLogReader,
        IPasswordCryptoService passwordCryptoService,
        IAccessCodeService accessCodeService,
        IAuditLogger auditLogger,
        IOptions<ShareOptions> shareOptions,
        IOptions<OidcAuthOptions> oidcAuthOptions)
    {
        _shareStore = shareStore;
        _auditLogReader = auditLogReader;
        _passwordCryptoService = passwordCryptoService;
        _accessCodeService = accessCodeService;
        _auditLogger = auditLogger;
        _shareOptions = shareOptions.Value;
        _oidcAuthOptions = oidcAuthOptions.Value;
        _adminRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.AdminRoleName) ? "Admin" : _oidcAuthOptions.AdminRoleName.Trim();
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var shares = await _shareStore.GetAllSharesAsync();

        if (!User.IsInRole(_adminRoleName))
        {
            var currentUser = GetCurrentUserIdentifier();
            shares = shares
                .Where(x => string.Equals(x.CreatedBy, currentUser, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        var items = shares
            .OrderByDescending(x => x.CreatedAtUtc)
            .Select(x => new AdminShareListItemViewModel
            {
                Id = x.Id,
                RecipientEmail = x.RecipientEmail,
                SharedUsername = x.SharedUsername,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                IsExpired = x.ExpiresAtUtc <= DateTime.UtcNow,
                RequireOidcLogin = x.RequireOidcLogin
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
        if (model.RequireOidcLogin && !_oidcAuthOptions.Enabled)
        {
            ModelState.AddModelError(nameof(model.RequireOidcLogin), "OIDC must be enabled before requiring Entra ID login for share links.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var accessCode = _accessCodeService.GenerateCode();
        var token = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var now = DateTime.UtcNow;
        var actorIdentifier = GetCurrentUserIdentifier();
        var actorType = GetCurrentActorType();

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
            CreatedBy = actorIdentifier,
            RequireOidcLogin = model.RequireOidcLogin
        };

        try
        {
            await _shareStore.UpsertShareAsync(share);
        }
        catch (RequestFailedException ex) when (ex.Status == 403)
        {
            await _auditLogger.LogAsync(
                actorType,
                actorIdentifier,
                "share.create",
                false,
                targetType: "PasswordShare",
                targetId: share.Id.ToString(),
                details: "Key Vault permission denied while creating share.");

            ModelState.AddModelError(string.Empty, "Share could not be created because the application identity is missing Key Vault secret write permission.");
            return View(model);
        }
        catch (RequestFailedException ex)
        {
            await _auditLogger.LogAsync(
                actorType,
                actorIdentifier,
                "share.create",
                false,
                targetType: "PasswordShare",
                targetId: share.Id.ToString(),
                details: $"Azure request failed: {ex.Message}");

            ModelState.AddModelError(string.Empty, "Share could not be created due to an Azure service error.");
            return View(model);
        }

        await _auditLogger.LogAsync(
            actorType,
            actorIdentifier,
            "share.create",
            true,
            targetType: "PasswordShare",
            targetId: share.Id.ToString(),
            details: $"Created share for {share.RecipientEmail} expiring at {share.ExpiresAtUtc:O}. requireOidcLogin={share.RequireOidcLogin}");

        var link = Url.Action("Access", "Share", new { token = share.AccessToken }, Request.Scheme) ?? string.Empty;

        return View("Created", new AdminShareCreatedViewModel
        {
            ShareId = share.Id,
            RecipientEmail = share.RecipientEmail,
            ShareLink = link,
            AccessCode = accessCode,
            ExpiresAtUtc = share.ExpiresAtUtc,
            RequireOidcLogin = share.RequireOidcLogin
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(Guid id)
    {
        var actorIdentifier = GetCurrentUserIdentifier();
        var actorType = GetCurrentActorType();
        var share = await _shareStore.GetShareByIdAsync(id);
        if (share is null)
        {
            await _auditLogger.LogAsync(actorType, actorIdentifier, "share.revoke", false, "PasswordShare", id.ToString(), "Share not found.");
            return NotFound();
        }

        if (!User.IsInRole(_adminRoleName) && !string.Equals(share.CreatedBy, actorIdentifier, StringComparison.OrdinalIgnoreCase))
        {
            await _auditLogger.LogAsync(actorType, actorIdentifier, "share.revoke", false, "PasswordShare", id.ToString(), "User attempted to revoke share they do not own.");
            return Forbid();
        }

        await _shareStore.DeleteShareAsync(id);

        await _auditLogger.LogAsync(actorType, actorIdentifier, "share.revoke", true, "PasswordShare", id.ToString());
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Audit(string? search, int page = 1, int pageSize = 100)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 10, 200);

        var logs = await _auditLogReader.GetLatestAsync(5000);

        var normalizedSearch = string.IsNullOrWhiteSpace(search) ? null : search.Trim();
        var filtered = string.IsNullOrWhiteSpace(normalizedSearch)
            ? logs
            : logs.Where(x =>
                   Contains(x.ActorType, normalizedSearch)
                || Contains(x.ActorIdentifier, normalizedSearch)
                || Contains(x.Operation, normalizedSearch)
                || Contains(x.TargetType, normalizedSearch)
                || Contains(x.TargetId, normalizedSearch)
                || Contains(x.IpAddress, normalizedSearch)
                || Contains(x.CorrelationId, normalizedSearch)
                || Contains(x.Details, normalizedSearch))
                .ToList();

        var totalCount = filtered.Count;
        var totalPages = totalCount == 0 ? 1 : (int)Math.Ceiling(totalCount / (double)pageSize);
        if (page > totalPages)
        {
            page = totalPages;
        }

        var pagedLogs = filtered
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var model = new AdminAuditViewModel
        {
            Logs = pagedLogs,
            Search = normalizedSearch,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };

        return View(model);
    }

    private static bool Contains(string? source, string value)
    {
        return !string.IsNullOrWhiteSpace(source)
            && source.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    private string GetCurrentUserIdentifier()
    {
                return User.FindFirstValue("preferred_username")
                             ?? User.FindFirstValue("email")
                             ?? User.FindFirstValue("upn")
                             ?? User.FindFirstValue("unique_name")
                             ?? User.FindFirstValue(ClaimTypes.Name)
                             ?? User.Identity?.Name
                             ?? User.FindFirstValue(ClaimTypes.Email)
                             ?? User.FindFirstValue("oid")
                             ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
                             ?? "unknown";
    }

    private string GetCurrentActorType()
    {
        return User.IsInRole(_adminRoleName) ? "admin" : "user";
    }
}
