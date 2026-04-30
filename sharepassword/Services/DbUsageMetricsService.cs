using Microsoft.EntityFrameworkCore;
using SharePassword.Data;
using SharePassword.Models;

namespace SharePassword.Services;

public sealed class DbUsageMetricsService : IUsageMetricsService
{
    public const string ShareCreatedKey = "share.created";
    public const string ShareAccessedKey = "share.accessed";
    public const string ShareRevokedKey = "share.revoked";
    public const string AdminLoginKey = "admin.login.success";
    public const string UserLoginKey = "user.login.success";
    public const string ExpiredDeletedKey = "share.expired.deleted";
    public const string ExpiredUnusedDeletedKey = "share.expired.unused.deleted";

    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IDatabaseOperationRunner _databaseOperationRunner;
    private readonly ILogger<DbUsageMetricsService> _logger;

    public DbUsageMetricsService(
        ISharePasswordDbContextFactory dbContextFactory,
        IDatabaseOperationRunner databaseOperationRunner,
        ILogger<DbUsageMetricsService> logger)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
        _logger = logger;
    }

    public bool IsSupported => true;

    public async Task RecordAsync(string metricKey, string actorType, string actorIdentifier, long increment = 1, string? relatedId = null, string? details = null, CancellationToken cancellationToken = default)
    {
        var normalizedKey = Trim(metricKey, 128);
        if (string.IsNullOrWhiteSpace(normalizedKey) || increment == 0)
        {
            return;
        }

        try
        {
            await _databaseOperationRunner.ExecuteAsync(
                "record usage metric",
                DatabaseOperationPurpose.Write,
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var counter = await dbContext.UsageMetricCounters.SingleOrDefaultAsync(x => x.Key == normalizedKey, innerCancellationToken);
                    if (counter is null)
                    {
                        counter = new UsageMetricCounter
                        {
                            Key = normalizedKey,
                            Count = increment,
                            UpdatedAtUtc = DateTime.UtcNow
                        };
                        dbContext.UsageMetricCounters.Add(counter);
                    }
                    else
                    {
                        counter.Count += increment;
                        counter.UpdatedAtUtc = DateTime.UtcNow;
                    }

                    dbContext.UsageMetricEvents.Add(new UsageMetricEvent
                    {
                        TimestampUtc = DateTime.UtcNow,
                        MetricKey = normalizedKey,
                        ActorType = Trim(actorType, 32),
                        ActorIdentifier = Trim(actorIdentifier, 256),
                        Increment = increment,
                        RelatedId = TrimNullable(relatedId, 128),
                        Details = TrimNullable(details, 2048)
                    });

                    await dbContext.SaveChangesAsync(innerCancellationToken);
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            _logger.LogWarning(exception, "Best-effort usage metric write failed for {MetricKey}. {DiagnosticMessage}", normalizedKey, exception.DiagnosticMessage);
        }
    }

    public async Task<DashboardMetricsSnapshot> GetDashboardSnapshotAsync(CancellationToken cancellationToken = default)
    {
        return await _databaseOperationRunner.ExecuteAsync(
            "load dashboard metrics",
            DatabaseOperationPurpose.Read,
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var counters = await dbContext.UsageMetricCounters
                    .AsNoTracking()
                    .Where(x => x.Key == ShareCreatedKey
                        || x.Key == ShareAccessedKey
                        || x.Key == AdminLoginKey
                        || x.Key == UserLoginKey
                        || x.Key == ExpiredDeletedKey
                        || x.Key == ExpiredUnusedDeletedKey)
                    .ToListAsync(innerCancellationToken);

                var lookup = counters.ToDictionary(x => x.Key, x => x.Count, StringComparer.OrdinalIgnoreCase);
                return new DashboardMetricsSnapshot
                {
                    TotalSharesCreated = lookup.GetValueOrDefault(ShareCreatedKey),
                    TotalShareAccesses = lookup.GetValueOrDefault(ShareAccessedKey),
                    AdminLogins = lookup.GetValueOrDefault(AdminLoginKey),
                    UserLogins = lookup.GetValueOrDefault(UserLoginKey),
                    ExpiredSharesDeleted = lookup.GetValueOrDefault(ExpiredDeletedKey),
                    ExpiredUnusedSharesDeleted = lookup.GetValueOrDefault(ExpiredUnusedDeletedKey)
                };
            },
            cancellationToken);
    }

    private static string Trim(string? value, int maxLength)
    {
        var normalized = (value ?? string.Empty).Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    private static string? TrimNullable(string? value, int maxLength)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        if (normalized is null)
        {
            return null;
        }

        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }
}