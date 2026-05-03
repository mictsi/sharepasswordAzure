using Azure.Core;
using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure;
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
        services.TryAddSingleton(new Func<IServiceProvider, ISystemConfigurationService>(CreateUnsupportedSystemConfigurationService));
        services.TryAddSingleton(new Func<IServiceProvider, ITimeZoneSettingsProvider>(CreateUnsupportedTimeZoneSettingsProvider));
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
                services.AddSingleton(CreateSqliteDbContextOptions(connectionString));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<SqliteSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.SqlServerBackend:
            {
                var sqlServerOptions = configuration.GetSection(SqlServerStorageOptions.SectionName).Get<SqlServerStorageOptions>() ?? new SqlServerStorageOptions();
                var connectionString = ResolveConnectionString(sqlServerOptions.ConnectionString, SqlServerStorageOptions.SectionName, backend);
                services.AddSingleton(CreateSqlServerDbContextOptions(connectionString));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<SqlServerSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.PostgresqlBackend:
            {
                var postgresqlOptions = configuration.GetSection(PostgresqlStorageOptions.SectionName).Get<PostgresqlStorageOptions>() ?? new PostgresqlStorageOptions();
                var connectionString = ResolveConnectionString(postgresqlOptions.ConnectionString, PostgresqlStorageOptions.SectionName, backend);
                services.AddSingleton(CreatePostgresqlDbContextOptions(connectionString));
                services.AddSingleton<ISharePasswordDbContextFactory, SharePasswordDbContextFactory<PostgresqlSharePasswordDbContext>>();
                RegisterDatabaseBackedPlatformServices(services);
                break;
            }

            case StorageOptions.AzureBackend:
                services.AddSingleton(new Func<IServiceProvider, SecretClient>(CreateSecretClient));
                services.AddSingleton(new Func<IServiceProvider, TableServiceClient>(CreateTableServiceClient));

                services.AddSingleton<KeyVaultStore>();
                services.AddSingleton(new Func<IServiceProvider, IShareStore>(CreateKeyVaultShareStore));
                services.AddSingleton<AuditTableStore>();
                services.AddSingleton(new Func<IServiceProvider, IAuditLogReader>(CreateAuditTableLogReader));
                services.AddSingleton(new Func<IServiceProvider, IAuditLogSink>(CreateAuditTableLogSink));
                return services;
        }

        services.AddSingleton<IShareStore, DbShareStore>();
        services.AddSingleton<DbAuditStore>();
        services.AddSingleton(new Func<IServiceProvider, IAuditLogReader>(CreateDbAuditLogReader));
        services.AddSingleton(new Func<IServiceProvider, IAuditLogSink>(CreateDbAuditLogSink));

        return services;
    }

    private static void RegisterDatabaseBackedPlatformServices(IServiceCollection services)
    {
        services.AddSingleton<DbSystemConfigurationService>();
        services.AddSingleton(new Func<IServiceProvider, ISystemConfigurationService>(CreateDbSystemConfigurationService));
        services.AddSingleton(new Func<IServiceProvider, ITimeZoneSettingsProvider>(CreateDbTimeZoneSettingsProvider));
        services.AddSingleton<ILocalUserService, DbLocalUserService>();
        services.AddSingleton<IUsageMetricsService, DbUsageMetricsService>();
        services.AddSingleton<INotificationEmailService, SmtpNotificationEmailService>();
        services.AddSingleton<IPlatformInitializationService, PlatformInitializationService>();
    }

    private static ISystemConfigurationService CreateUnsupportedSystemConfigurationService(IServiceProvider provider) =>
        provider.GetRequiredService<UnsupportedSystemConfigurationService>();

    private static ITimeZoneSettingsProvider CreateUnsupportedTimeZoneSettingsProvider(IServiceProvider provider) =>
        provider.GetRequiredService<UnsupportedSystemConfigurationService>();

    private static ISystemConfigurationService CreateDbSystemConfigurationService(IServiceProvider provider) =>
        provider.GetRequiredService<DbSystemConfigurationService>();

    private static ITimeZoneSettingsProvider CreateDbTimeZoneSettingsProvider(IServiceProvider provider) =>
        provider.GetRequiredService<DbSystemConfigurationService>();

    private static IShareStore CreateKeyVaultShareStore(IServiceProvider provider) =>
        provider.GetRequiredService<KeyVaultStore>();

    private static IAuditLogReader CreateAuditTableLogReader(IServiceProvider provider) =>
        provider.GetRequiredService<AuditTableStore>();

    private static IAuditLogSink CreateAuditTableLogSink(IServiceProvider provider) =>
        provider.GetRequiredService<AuditTableStore>();

    private static IAuditLogReader CreateDbAuditLogReader(IServiceProvider provider) =>
        provider.GetRequiredService<DbAuditStore>();

    private static IAuditLogSink CreateDbAuditLogSink(IServiceProvider provider) =>
        provider.GetRequiredService<DbAuditStore>();

    private static DbContextOptions<SqliteSharePasswordDbContext> CreateSqliteDbContextOptions(string connectionString)
    {
        var builder = new DbContextOptionsBuilder<SqliteSharePasswordDbContext>();
        builder.UseSqlite(connectionString, new Action<SqliteDbContextOptionsBuilder>(ConfigureSqliteMigrationsAssembly));
        return builder.Options;
    }

    private static DbContextOptions<SqlServerSharePasswordDbContext> CreateSqlServerDbContextOptions(string connectionString)
    {
        var builder = new DbContextOptionsBuilder<SqlServerSharePasswordDbContext>();
        builder.UseSqlServer(connectionString, new Action<SqlServerDbContextOptionsBuilder>(ConfigureSqlServerMigrationsAssembly));
        return builder.Options;
    }

    private static DbContextOptions<PostgresqlSharePasswordDbContext> CreatePostgresqlDbContextOptions(string connectionString)
    {
        var builder = new DbContextOptionsBuilder<PostgresqlSharePasswordDbContext>();
        builder.UseNpgsql(connectionString, new Action<NpgsqlDbContextOptionsBuilder>(ConfigurePostgresqlMigrationsAssembly));
        return builder.Options;
    }

    private static void ConfigureSqliteMigrationsAssembly(SqliteDbContextOptionsBuilder sqlite) =>
        sqlite.MigrationsAssembly(typeof(SqliteSharePasswordDbContext).Assembly.FullName);

    private static void ConfigureSqlServerMigrationsAssembly(SqlServerDbContextOptionsBuilder sqlServer) =>
        sqlServer.MigrationsAssembly(typeof(SqlServerSharePasswordDbContext).Assembly.FullName);

    private static void ConfigurePostgresqlMigrationsAssembly(NpgsqlDbContextOptionsBuilder npgsql) =>
        npgsql.MigrationsAssembly(typeof(PostgresqlSharePasswordDbContext).Assembly.FullName);

    private static SecretClient CreateSecretClient(IServiceProvider provider)
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
    }

    private static TableServiceClient CreateTableServiceClient(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptions<AzureTableAuditOptions>>().Value;
        if (string.IsNullOrWhiteSpace(options.ServiceSasUrl))
        {
            throw new InvalidOperationException("AzureStorage:TableAudit:ServiceSasUrl must be configured when Storage:Backend=azure.");
        }

        return new TableServiceClient(new Uri(options.ServiceSasUrl));
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
        var startupOperation = new StartupDatabaseOperation(dbContextFactory);

        if (applyMigrationsOnStartup)
        {
            await databaseOperationRunner.ExecuteAsync(
                "apply startup migrations",
                DatabaseOperationPurpose.Startup,
                new Func<CancellationToken, Task>(startupOperation.ApplyMigrationsAsync),
                cancellationToken);

            return;
        }

        var canConnect = await databaseOperationRunner.ExecuteAsync(
            "startup connectivity probe",
            DatabaseOperationPurpose.HealthCheck,
            new Func<CancellationToken, Task<bool>>(startupOperation.CanConnectAsync),
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

    private sealed class StartupDatabaseOperation
    {
        private readonly ISharePasswordDbContextFactory _dbContextFactory;

        public StartupDatabaseOperation(ISharePasswordDbContextFactory dbContextFactory)
        {
            _dbContextFactory = dbContextFactory;
        }

        public async Task ApplyMigrationsAsync(CancellationToken cancellationToken)
        {
            await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            await dbContext.Database.MigrateAsync(cancellationToken);
        }

        public async Task<bool> CanConnectAsync(CancellationToken cancellationToken)
        {
            await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            return await dbContext.Database.CanConnectAsync(cancellationToken);
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
