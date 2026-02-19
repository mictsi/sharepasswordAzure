using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public class ExpiredShareCleanupService : BackgroundService
{
    private readonly IShareStore _shareStore;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<ExpiredShareCleanupService> _logger;
    private readonly ShareOptions _shareOptions;

    public ExpiredShareCleanupService(
        IShareStore shareStore,
        IAuditLogger auditLogger,
        IOptions<ShareOptions> options,
        ILogger<ExpiredShareCleanupService> logger)
    {
        _shareStore = shareStore;
        _auditLogger = auditLogger;
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
                var deletedCount = await _shareStore.DeleteExpiredSharesAsync(DateTime.UtcNow, stoppingToken);

                if (deletedCount > 0)
                {
                    await _auditLogger.LogAsync(
                        "system",
                        "cleanup-service",
                        "cleanup.expired-shares",
                        true,
                        targetType: "PasswordShare",
                        details: $"Deleted {deletedCount} expired shares.",
                        cancellationToken: stoppingToken);
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
