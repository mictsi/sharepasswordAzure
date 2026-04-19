using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text.Json;
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
    private readonly IApplicationTime _applicationTime;
    private readonly ShareOptions _shareOptions;
    private readonly OidcAuthOptions _oidcAuthOptions;
    private readonly string _adminRoleName;

    public AdminController(
        IShareStore shareStore,
        IAuditLogReader auditLogReader,
        IPasswordCryptoService passwordCryptoService,
        IAccessCodeService accessCodeService,
        IAuditLogger auditLogger,
        IApplicationTime applicationTime,
        IOptions<ShareOptions> shareOptions,
        IOptions<OidcAuthOptions> oidcAuthOptions)
    {
        _shareStore = shareStore;
        _auditLogReader = auditLogReader;
        _passwordCryptoService = passwordCryptoService;
        _accessCodeService = accessCodeService;
        _auditLogger = auditLogger;
        _applicationTime = applicationTime;
        _shareOptions = shareOptions.Value;
        _oidcAuthOptions = oidcAuthOptions.Value;
        _adminRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.AdminRoleName) ? "Admin" : _oidcAuthOptions.AdminRoleName.Trim();
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var shares = await _shareStore.GetAllSharesAsync();
        var nowUtc = _applicationTime.UtcNow;

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
                IsExpired = x.ExpiresAtUtc <= nowUtc,
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
        model.RecipientEmail = (model.RecipientEmail ?? string.Empty).Trim();
        model.SharedUsername = (model.SharedUsername ?? string.Empty).Trim();
        model.Password = (model.Password ?? string.Empty).Replace("\0", string.Empty);
        model.Instructions = (model.Instructions ?? string.Empty).Replace("\0", string.Empty);

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
        var now = _applicationTime.UtcNow;
        var actorIdentifier = GetCurrentUserIdentifier();
        var actorType = GetCurrentActorType();

        var share = new PasswordShare
        {
            Id = Guid.NewGuid(),
            RecipientEmail = model.RecipientEmail.Trim().ToLowerInvariant(),
            SharedUsername = model.SharedUsername.Trim(),
            EncryptedPassword = _passwordCryptoService.Encrypt(model.Password),
            Instructions = model.Instructions,
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
        catch (DbUpdateException ex)
        {
            await _auditLogger.LogAsync(
                actorType,
                actorIdentifier,
                "share.create",
                false,
                targetType: "PasswordShare",
                targetId: share.Id.ToString(),
                details: $"Database write failed: {ex.GetBaseException().Message}");

            ModelState.AddModelError(string.Empty, "Share could not be created due to a database error.");
            return View(model);
        }

        await _auditLogger.LogAsync(
            actorType,
            actorIdentifier,
            "share.create",
            true,
            targetType: "PasswordShare",
            targetId: share.Id.ToString(),
            details: $"Created share for {share.RecipientEmail} expiring at {_applicationTime.FormatUtcForDisplay(share.ExpiresAtUtc)} ({_applicationTime.TimeZoneId}). requireOidcLogin={share.RequireOidcLogin}");

        var link = ApplicationPathHelper.BuildAbsoluteAppUrl(Request, $"/s/{share.AccessToken}");

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
    public async Task<IActionResult> Audit(string? search, string? range = null, int page = 1, int pageSize = 100)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 10, 200);

        var logs = await _auditLogReader.GetLatestAsync(5000);
        var normalizedRange = AdminAuditRangeOption.Normalize(range);
        var filteredByRange = ApplyAuditRange(logs, normalizedRange);

        var normalizedSearch = string.IsNullOrWhiteSpace(search) ? null : search.Trim();
        var filtered = string.IsNullOrWhiteSpace(normalizedSearch)
            ? filteredByRange
            : filteredByRange.Where(x =>
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
            ExportLogs = filtered.OrderByDescending(x => x.TimestampUtc).ToList(),
            Search = normalizedSearch,
            SelectedRange = normalizedRange,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };

        return View(model);
    }

    [HttpGet]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> ExportAuditJson(string? search, string? range = null)
    {
        var logs = await _auditLogReader.GetLatestAsync(5000);
        var normalizedRange = AdminAuditRangeOption.Normalize(range);
        var filteredByRange = ApplyAuditRange(logs, normalizedRange);
        var normalizedSearch = string.IsNullOrWhiteSpace(search) ? null : search.Trim();

        var filtered = string.IsNullOrWhiteSpace(normalizedSearch)
            ? filteredByRange
            : filteredByRange.Where(x =>
                   Contains(x.ActorType, normalizedSearch)
                || Contains(x.ActorIdentifier, normalizedSearch)
                || Contains(x.Operation, normalizedSearch)
                || Contains(x.TargetType, normalizedSearch)
                || Contains(x.TargetId, normalizedSearch)
                || Contains(x.IpAddress, normalizedSearch)
                || Contains(x.CorrelationId, normalizedSearch)
                || Contains(x.Details, normalizedSearch))
                .ToList();

        var payload = filtered
            .OrderByDescending(x => x.TimestampUtc)
            .Select(log => new
            {
                log.Id,
                log.TimestampUtc,
                Timestamp = _applicationTime.FormatUtcForDisplay(log.TimestampUtc),
                TimeZone = _applicationTime.TimeZoneId,
                log.ActorType,
                log.ActorIdentifier,
                log.Operation,
                log.Success,
                log.TargetType,
                log.TargetId,
                log.IpAddress,
                log.UserAgent,
                log.CorrelationId,
                log.Details
            })
            .ToList();

        var fileName = $"audit-logs-{normalizedRange}-{_applicationTime.UtcNow:yyyyMMddHHmmss}.json";
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        return File(System.Text.Encoding.UTF8.GetBytes(json), "application/json", fileName);
    }

    private static bool Contains(string? source, string value)
    {
        return !string.IsNullOrWhiteSpace(source)
            && source.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    private List<AuditLog> ApplyAuditRange(IReadOnlyCollection<AuditLog> logs, string normalizedRange)
    {
        var now = _applicationTime.Now;
        var rangeStartUtc = normalizedRange switch
        {
            AdminAuditRangeOption.LastDay => now.AddDays(-1).UtcDateTime,
            AdminAuditRangeOption.ThisWeek => GetStartOfWeek(now).UtcDateTime,
            AdminAuditRangeOption.ThisMonth => new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, now.Offset).UtcDateTime,
            AdminAuditRangeOption.Last3Months => now.AddMonths(-3).UtcDateTime,
            AdminAuditRangeOption.Last6Months => now.AddMonths(-6).UtcDateTime,
            _ => (DateTime?)null
        };

        return rangeStartUtc is null
            ? logs.OrderByDescending(x => x.TimestampUtc).ToList()
            : logs.Where(x => x.TimestampUtc >= rangeStartUtc.Value)
                .OrderByDescending(x => x.TimestampUtc)
                .ToList();
    }

    private static DateTimeOffset GetStartOfWeek(DateTimeOffset value)
    {
        var diff = ((int)value.DayOfWeek - (int)DayOfWeek.Monday + 7) % 7;
        var start = value.Date.AddDays(-diff);
        return new DateTimeOffset(start, value.Offset);
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
