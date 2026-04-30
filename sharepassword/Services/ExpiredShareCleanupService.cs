using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public class ExpiredShareCleanupService : BackgroundService
{
    private readonly IShareStore _shareStore;
    private readonly IAuditLogger _auditLogger;
    private readonly IApplicationTime _applicationTime;
    private readonly IUsageMetricsService _usageMetricsService;
    private readonly ILogger<ExpiredShareCleanupService> _logger;
    private readonly ShareOptions _shareOptions;

    public ExpiredShareCleanupService(
        IShareStore shareStore,
        IAuditLogger auditLogger,
        IApplicationTime applicationTime,
        IUsageMetricsService usageMetricsService,
        IOptions<ShareOptions> options,
        ILogger<ExpiredShareCleanupService> logger)
    {
        _shareStore = shareStore;
        _auditLogger = auditLogger;
        _applicationTime = applicationTime;
        _usageMetricsService = usageMetricsService;
        _logger = logger;
        _shareOptions = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = Math.Max(15, _shareOptions.CleanupIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var nowUtc = _applicationTime.UtcNow;
                var expiredShares = await _shareStore.GetAllSharesAsync(stoppingToken);
                var expiredUnusedCount = expiredShares.Count(x => x.ExpiresAtUtc <= nowUtc && !x.LastAccessedAtUtc.HasValue);
                var deletedCount = await _shareStore.DeleteExpiredSharesAsync(nowUtc, stoppingToken);

                if (deletedCount > 0)
                {
                    await _auditLogger.LogAsync(
                        "system",
                        "cleanup-service",
                        "cleanup.expired-shares",
                        true,
                        targetType: "PasswordShare",
                        details: $"Deleted {deletedCount} expired shares. Unused expired shares={expiredUnusedCount}.",
                        cancellationToken: stoppingToken);
                    await _usageMetricsService.RecordAsync(DbUsageMetricsService.ExpiredDeletedKey, "system", "cleanup-service", deletedCount, details: "Expired shares deleted during cleanup.", cancellationToken: stoppingToken);

                    if (expiredUnusedCount > 0)
                    {
                        await _usageMetricsService.RecordAsync(DbUsageMetricsService.ExpiredUnusedDeletedKey, "system", "cleanup-service", expiredUnusedCount, details: "Expired unused shares deleted during cleanup.", cancellationToken: stoppingToken);
                    }
                }
            }
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while cleaning expired shares.");
            }

            await Task.Delay(TimeSpan.FromSeconds(interval), stoppingToken);
        }
    }
}
