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
    private readonly ILocalUserService _localUserService;
    private readonly IUsageMetricsService _usageMetricsService;
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
        ILocalUserService localUserService,
        IUsageMetricsService usageMetricsService,
        IOptions<ShareOptions> shareOptions,
        IOptions<OidcAuthOptions> oidcAuthOptions)
    {
        _shareStore = shareStore;
        _auditLogReader = auditLogReader;
        _passwordCryptoService = passwordCryptoService;
        _accessCodeService = accessCodeService;
        _auditLogger = auditLogger;
        _applicationTime = applicationTime;
        _localUserService = localUserService;
        _usageMetricsService = usageMetricsService;
        _shareOptions = shareOptions.Value;
        _oidcAuthOptions = oidcAuthOptions.Value;
        _adminRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.AdminRoleName) ? "Admin" : _oidcAuthOptions.AdminRoleName.Trim();
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? search, string? status = null)
    {
        var shares = await _shareStore.GetAllSharesAsync();
        var nowUtc = _applicationTime.UtcNow;
        var currentUser = GetCurrentUserIdentifier();
        var isAdmin = User.IsInRole(_adminRoleName);

        if (!isAdmin)
        {
            shares = shares
                .Where(x => string.Equals(x.CreatedBy, currentUser, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        var normalizedSearch = NormalizeFilter(search) ?? string.Empty;
        var normalizedStatus = AdminShareStatusOption.Normalize(status);

        var allItems = shares
            .OrderByDescending(x => x.CreatedAtUtc)
            .Select(x => new AdminShareListItemViewModel
            {
                Id = x.Id,
                RecipientEmail = x.RecipientEmail,
                SharedUsername = x.SharedUsername,
                CreatedBy = x.CreatedBy,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                LastAccessedAtUtc = x.LastAccessedAtUtc,
                IsExpired = x.ExpiresAtUtc <= nowUtc,
                IsExpiringSoon = x.ExpiresAtUtc > nowUtc && x.ExpiresAtUtc <= nowUtc.AddHours(24),
                RequireOidcLogin = x.RequireOidcLogin
            })
            .ToList();

        var filteredItems = allItems
            .Where(x => MatchesDashboardSearch(x, normalizedSearch) && MatchesDashboardStatus(x, normalizedStatus))
            .ToList();

        var auditLogs = await _auditLogReader.GetLatestAsync(5000);
        var visibleAuditLogs = isAdmin
            ? auditLogs
            : auditLogs.Where(x => string.Equals(x.ActorIdentifier, currentUser, StringComparison.OrdinalIgnoreCase)).ToList();
        var dashboardMetrics = await _usageMetricsService.GetDashboardSnapshotAsync();

        var model = new AdminDashboardViewModel
        {
            Search = normalizedSearch,
            SelectedStatus = normalizedStatus,
            ActiveCount = allItems.Count(x => !x.IsExpired),
            ExpiringSoonCount = allItems.Count(x => x.IsExpiringSoon),
            AccessedCount = allItems.Count(x => x.HasBeenAccessed),
            RevokedCount = visibleAuditLogs.Count(x => x.Success && string.Equals(x.Operation, "share.revoke", StringComparison.OrdinalIgnoreCase)),
            TotalVisibleShares = allItems.Count,
            TotalSharesCreatedKpi = dashboardMetrics.TotalSharesCreated,
            TotalShareAccessesKpi = dashboardMetrics.TotalShareAccesses,
            AdminLoginsKpi = dashboardMetrics.AdminLogins,
            ExpiredSharesDeletedKpi = dashboardMetrics.ExpiredSharesDeleted,
            ExpiredUnusedSharesDeletedKpi = dashboardMetrics.ExpiredUnusedSharesDeleted,
            Shares = filteredItems
        };

        return View(model);
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
            ModelState.AddModelError(nameof(model.RequireOidcLogin), "Microsoft Entra ID sign-in must be enabled before requiring it for share links.");
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
        await _usageMetricsService.RecordAsync(DbUsageMetricsService.ShareCreatedKey, actorType, actorIdentifier, relatedId: share.Id.ToString(), details: $"Share created for {share.RecipientEmail}.");
        await _localUserService.RecordShareCreatedAsync(actorIdentifier);

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
        await _usageMetricsService.RecordAsync(DbUsageMetricsService.ShareRevokedKey, actorType, actorIdentifier, relatedId: id.ToString(), details: "Share revoked.");
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    [Authorize(Policy = "AuditAccess")]
    public async Task<IActionResult> Audit(string? search, string? actor, string? operation, string? success, string? range = null, int page = 1, int pageSize = 100)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 10, 200);

        var logs = await _auditLogReader.GetLatestAsync(5000);
        var normalizedRange = AdminAuditRangeOption.Normalize(range);
        var normalizedSearch = NormalizeFilter(search);
        var normalizedActor = NormalizeFilter(actor);
        var normalizedOperation = NormalizeOperation(operation);
        var normalizedSuccess = AdminAuditSuccessOption.Normalize(success);
        var filteredByRange = ApplyAuditRange(logs, normalizedRange);
        var availableOperations = filteredByRange
            .Select(x => x.Operation)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var filtered = ApplyAuditFilters(filteredByRange, normalizedSearch, normalizedActor, normalizedOperation, normalizedSuccess);

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
            Actor = normalizedActor,
            SelectedRange = normalizedRange,
            SelectedOperation = normalizedOperation,
            SelectedSuccess = normalizedSuccess,
            AvailableOperations = availableOperations,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };

        return View(model);
    }

    [HttpGet]
    [Authorize(Policy = "AuditAccess")]
    public async Task<IActionResult> ExportAuditJson(string? search, string? actor, string? operation, string? success, string? range = null)
    {
        var logs = await _auditLogReader.GetLatestAsync(5000);
        var normalizedRange = AdminAuditRangeOption.Normalize(range);
        var filteredByRange = ApplyAuditRange(logs, normalizedRange);
        var normalizedSearch = NormalizeFilter(search);
        var normalizedActor = NormalizeFilter(actor);
        var normalizedOperation = NormalizeOperation(operation);
        var normalizedSuccess = AdminAuditSuccessOption.Normalize(success);
        var filtered = ApplyAuditFilters(filteredByRange, normalizedSearch, normalizedActor, normalizedOperation, normalizedSuccess);

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

    private static bool MatchesDashboardSearch(AdminShareListItemViewModel item, string search)
    {
        return string.IsNullOrWhiteSpace(search)
            || Contains(item.RecipientEmail, search)
            || Contains(item.SharedUsername, search)
            || Contains(item.CreatedBy, search);
    }

    private static bool MatchesDashboardStatus(AdminShareListItemViewModel item, string status)
    {
        return AdminShareStatusOption.Normalize(status) switch
        {
            AdminShareStatusOption.Active => !item.IsExpired,
            AdminShareStatusOption.ExpiringSoon => item.IsExpiringSoon,
            AdminShareStatusOption.Accessed => item.HasBeenAccessed,
            AdminShareStatusOption.Expired => item.IsExpired,
            _ => true
        };
    }

    private static string? NormalizeFilter(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static string NormalizeOperation(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? AdminAuditOperationOption.All : value.Trim();
    }

    private static List<AuditLog> ApplyAuditFilters(
        IReadOnlyCollection<AuditLog> logs,
        string? search,
        string? actor,
        string operation,
        string success)
    {
        return logs.Where(x =>
                (string.IsNullOrWhiteSpace(actor)
                    || Contains(x.ActorType, actor)
                    || Contains(x.ActorIdentifier, actor))
                && (string.Equals(operation, AdminAuditOperationOption.All, StringComparison.Ordinal)
                    || string.Equals(x.Operation, operation, StringComparison.OrdinalIgnoreCase))
                && (AdminAuditSuccessOption.Normalize(success) switch
                {
                    AdminAuditSuccessOption.Success => x.Success,
                    AdminAuditSuccessOption.Failure => !x.Success,
                    _ => true
                })
                && (string.IsNullOrWhiteSpace(search)
                    || Contains(x.ActorType, search)
                    || Contains(x.ActorIdentifier, search)
                    || Contains(x.Operation, search)
                    || Contains(x.TargetType, search)
                    || Contains(x.TargetId, search)
                    || Contains(x.IpAddress, search)
                    || Contains(x.CorrelationId, search)
                    || Contains(x.Details, search)))
            .OrderByDescending(x => x.TimestampUtc)
            .ToList();
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
