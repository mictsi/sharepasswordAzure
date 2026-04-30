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

    public DbUsageMetricsService(ISharePasswordDbContextFactory dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    public bool IsSupported => true;

    public async Task RecordAsync(string metricKey, string actorType, string actorIdentifier, long increment = 1, string? relatedId = null, string? details = null, CancellationToken cancellationToken = default)
    {
        var normalizedKey = Trim(metricKey, 128);
        if (string.IsNullOrWhiteSpace(normalizedKey) || increment == 0)
        {
            return;
        }

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var counter = await dbContext.UsageMetricCounters.SingleOrDefaultAsync(x => x.Key == normalizedKey, cancellationToken);
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

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<DashboardMetricsSnapshot> GetDashboardSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var counters = await dbContext.UsageMetricCounters
            .AsNoTracking()
            .Where(x => x.Key == ShareCreatedKey
                || x.Key == ShareAccessedKey
                || x.Key == AdminLoginKey
                || x.Key == UserLoginKey
                || x.Key == ExpiredDeletedKey
                || x.Key == ExpiredUnusedDeletedKey)
            .ToListAsync(cancellationToken);

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