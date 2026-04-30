using Azure.Core;
using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SharePassword.Options;
using SharePassword.Services;

namespace SharePassword.Data;

public static class DatabaseRegistrationExtensions
{
    public static IServiceCollection AddConfiguredStorageBackend(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<StorageOptions>(configuration.GetSection(StorageOptions.SectionName));
        services.Configure<SqliteStorageOptions>(configuration.GetSection(SqliteStorageOptions.SectionName));
        services.Configure<SqlServerStorageOptions>(configuration.GetSection(SqlServerStorageOptions.SectionName));
        services.Configure<PostgresqlStorageOptions>(configuration.GetSection(PostgresqlStorageOptions.SectionName));
        services.Configure<AzureKeyVaultOptions>(configuration.GetSection(AzureKeyVaultOptions.SectionName));
        services.Configure<AzureTableAuditOptions>(configuration.GetSection(AzureTableAuditOptions.SectionName));
        services.Configure<MailOptions>(configuration.GetSection(MailOptions.SectionName));

        services.TryAddSingleton<UnsupportedSystemConfigurationService>();
        services.TryAddSingleton<ISystemConfigurationService>(provider => provider.GetRequiredService<UnsupportedSystemConfigurationService>());
        services.TryAddSingleton<ITimeZoneSettingsProvider>(provider => provider.GetRequiredService<UnsupportedSystemConfigurationService>());
        services.TryAddSingleton<ILocalUserService, UnsupportedLocalUserService>();
        services.TryAddSingleton<IUsageMetricsService, UnsupportedUsageMetricsService>();
        services.TryAddSingleton<INotificationEmailService, UnsupportedNotificationEmailService>();
        services.TryAddSingleton<IPlatformInitializationService, UnsupportedPlatformInitializationService>();

        var storageOptions = configuration.GetSection(StorageOptions.SectionName).Get<StorageOptions>() ?? new StorageOptions();
        var backend = StorageOptions.NormalizeBackend(storageOptions.Backend);

        switch (backend)
        {
            case StorageOptions.SqliteBackend:
            {
                var sqliteOptions = configuration.GetSection(SqliteStorageOptions.SectionName).Get<SqliteStorageOptions>() ?? new SqliteStorageOptions();
                var connectionString = ResolveConnectionString(sqliteOptions.ConnectionString, SqliteStorageOptions.SectionName, backend);
                EnsureSqliteDatabasePath(connectionString);
                services.AddDbContextFactory<SqliteSharePasswordDbContext>(options =>
                    options.UseSqlite(connectionString, sqlite =>
                        sqlite.MigrationsAssembly(typeof(SqliteSharePasswordDbContext).Assembly.FullName)));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<SqliteSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.SqlServerBackend:
            {
                var sqlServerOptions = configuration.GetSection(SqlServerStorageOptions.SectionName).Get<SqlServerStorageOptions>() ?? new SqlServerStorageOptions();
                var connectionString = ResolveConnectionString(sqlServerOptions.ConnectionString, SqlServerStorageOptions.SectionName, backend);
                services.AddDbContextFactory<SqlServerSharePasswordDbContext>(options =>
                    options.UseSqlServer(connectionString, sqlServer =>
                    {
                        sqlServer.MigrationsAssembly(typeof(SqlServerSharePasswordDbContext).Assembly.FullName);
                    }));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<SqlServerSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.PostgresqlBackend:
            {
                var postgresqlOptions = configuration.GetSection(PostgresqlStorageOptions.SectionName).Get<PostgresqlStorageOptions>() ?? new PostgresqlStorageOptions();
                var connectionString = ResolveConnectionString(postgresqlOptions.ConnectionString, PostgresqlStorageOptions.SectionName, backend);
                services.AddDbContextFactory<PostgresqlSharePasswordDbContext>(options =>
                    options.UseNpgsql(connectionString, npgsql =>
                    {
                        npgsql.MigrationsAssembly(typeof(PostgresqlSharePasswordDbContext).Assembly.FullName);
                    }));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<PostgresqlSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.AzureBackend:
                services.AddSingleton(provider =>
                {
                    var options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value;
                    if (string.IsNullOrWhiteSpace(options.VaultUri))
                    {
                        throw new InvalidOperationException("AzureStorage:KeyVault:VaultUri must be configured when Storage:Backend=azure.");
                    }

                    TokenCredential credential;
                    if (!string.IsNullOrWhiteSpace(options.TenantId)
                        && !string.IsNullOrWhiteSpace(options.ClientId)
                        && !string.IsNullOrWhiteSpace(options.ClientSecret))
                    {
                        credential = new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret);
                    }
                    else
                    {
                        credential = new DefaultAzureCredential();
                    }

                    return new SecretClient(new Uri(options.VaultUri), credential);
                });

                services.AddSingleton(provider =>
                {
                    var options = provider.GetRequiredService<IOptions<AzureTableAuditOptions>>().Value;
                    if (string.IsNullOrWhiteSpace(options.ServiceSasUrl))
                    {
                        throw new InvalidOperationException("AzureStorage:TableAudit:ServiceSasUrl must be configured when Storage:Backend=azure.");
                    }

                    return new TableServiceClient(new Uri(options.ServiceSasUrl));
                });

                services.AddSingleton<KeyVaultStore>();
                services.AddSingleton<IShareStore>(provider => provider.GetRequiredService<KeyVaultStore>());
                services.AddSingleton<AuditTableStore>();
                services.AddSingleton<IAuditLogReader>(provider => provider.GetRequiredService<AuditTableStore>());
                services.AddSingleton<IAuditLogSink>(provider => provider.GetRequiredService<AuditTableStore>());
                return services;
        }

        services.AddSingleton<IShareStore, DbShareStore>();
        services.AddSingleton<DbAuditStore>();
        services.AddSingleton<IAuditLogReader>(provider => provider.GetRequiredService<DbAuditStore>());
        services.AddSingleton<IAuditLogSink>(provider => provider.GetRequiredService<DbAuditStore>());

        return services;
    }

    private static void RegisterDatabaseBackedPlatformServices(IServiceCollection services)
    {
        services.AddSingleton<DbSystemConfigurationService>();
        services.AddSingleton<ISystemConfigurationService>(provider => provider.GetRequiredService<DbSystemConfigurationService>());
        services.AddSingleton<ITimeZoneSettingsProvider>(provider => provider.GetRequiredService<DbSystemConfigurationService>());
        services.AddSingleton<ILocalUserService, DbLocalUserService>();
        services.AddSingleton<IUsageMetricsService, DbUsageMetricsService>();
        services.AddSingleton<INotificationEmailService, SmtpNotificationEmailService>();
        services.AddSingleton<IPlatformInitializationService, PlatformInitializationService>();
    }

    public static async Task ApplyConfiguredStorageMigrationsAsync(this IServiceProvider services, CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var storageOptions = scope.ServiceProvider.GetRequiredService<IOptions<StorageOptions>>().Value;
        var backend = StorageOptions.NormalizeBackend(storageOptions.Backend);
        var databaseOperationRunner = scope.ServiceProvider.GetRequiredService<IDatabaseOperationRunner>();

        if (backend == StorageOptions.AzureBackend)
        {
            return;
        }

        var applyMigrationsOnStartup = backend switch
        {
            StorageOptions.SqliteBackend => scope.ServiceProvider.GetRequiredService<IOptions<SqliteStorageOptions>>().Value.ApplyMigrationsOnStartup,
            StorageOptions.SqlServerBackend => scope.ServiceProvider.GetRequiredService<IOptions<SqlServerStorageOptions>>().Value.ApplyMigrationsOnStartup,
            StorageOptions.PostgresqlBackend => scope.ServiceProvider.GetRequiredService<IOptions<PostgresqlStorageOptions>>().Value.ApplyMigrationsOnStartup,
            _ => false
        };

        var dbContextFactory = scope.ServiceProvider.GetRequiredService<ISharePasswordDbContextFactory>();

        if (applyMigrationsOnStartup)
        {
            await databaseOperationRunner.ExecuteAsync(
                "apply startup migrations",
                DatabaseOperationPurpose.Startup,
                async innerCancellationToken =>
                {
                    await using var dbContext = await dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    await dbContext.Database.MigrateAsync(innerCancellationToken);
                },
                cancellationToken);

            return;
        }

        var canConnect = await databaseOperationRunner.ExecuteAsync(
            "startup connectivity probe",
            DatabaseOperationPurpose.HealthCheck,
            async innerCancellationToken =>
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                return await dbContext.Database.CanConnectAsync(innerCancellationToken);
            },
            cancellationToken);

        if (!canConnect)
        {
            throw new DatabaseOperationException(
                "startup connectivity probe",
                "The application could not connect to the configured database.",
                "Database connectivity probe returned false.",
                true);
        }
    }

    private static string ResolveConnectionString(string? connectionString, string sectionName, string backend)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException($"{sectionName}:ConnectionString must be configured when Storage:Backend={backend}.");
        }

        return connectionString.Trim();
    }

    private static void EnsureSqliteDatabasePath(string connectionString)
    {
        var sqlite = new SqliteConnectionStringBuilder(connectionString);
        if (string.IsNullOrWhiteSpace(sqlite.DataSource) || string.Equals(sqlite.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var dataSource = sqlite.DataSource;
        if (Uri.TryCreate(dataSource, UriKind.Absolute, out var fileUri) && fileUri.IsFile)
        {
            dataSource = fileUri.LocalPath;
        }
        else if (!Path.IsPathRooted(dataSource))
        {
            dataSource = Path.GetFullPath(dataSource, Directory.GetCurrentDirectory());
        }

        var directory = Path.GetDirectoryName(dataSource);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }
}