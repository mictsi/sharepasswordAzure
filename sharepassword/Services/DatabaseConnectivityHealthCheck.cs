using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SharePassword.Data;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class DatabaseConnectivityHealthCheck : IHealthCheck
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IOptions<StorageOptions> _storageOptions;

    public DatabaseConnectivityHealthCheck(IServiceScopeFactory serviceScopeFactory, IOptions<StorageOptions> storageOptions)
    {
        _serviceScopeFactory = serviceScopeFactory;
        _storageOptions = storageOptions;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var backend = StorageOptions.NormalizeBackend(_storageOptions.Value.Backend);
        if (backend == StorageOptions.AzureBackend)
        {
            return HealthCheckResult.Healthy("Database health check is not required for the Azure storage backend.");
        }

        using var scope = _serviceScopeFactory.CreateScope();
        var dbContextFactory = scope.ServiceProvider.GetRequiredService<ISharePasswordDbContextFactory>();
        var databaseOperationRunner = scope.ServiceProvider.GetRequiredService<IDatabaseOperationRunner>();

        try
        {
            var canConnect = await databaseOperationRunner.ExecuteAsync(
                "health check connectivity probe",
                DatabaseOperationPurpose.HealthCheck,
                async innerCancellationToken =>
                {
                    await using var dbContext = await dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    return await dbContext.Database.CanConnectAsync(innerCancellationToken);
                },
                cancellationToken);

            return canConnect
                ? HealthCheckResult.Healthy($"Database backend '{backend}' is reachable.")
                : HealthCheckResult.Unhealthy("The application could not connect to the configured database.");
        }
        catch (DatabaseOperationException exception)
        {
            return HealthCheckResult.Unhealthy(exception.UserMessage, exception);
        }
    }
}