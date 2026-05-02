using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SharePassword.Models;

namespace SharePassword.Data;

public abstract class SharePasswordDbContext : DbContext
{
    private static readonly ValueConverter<DateTime, DateTime> UtcDateTimeConverter = new(
        value => EnsureUtc(value),
        value => EnsureUtc(value));

    private static readonly ValueConverter<DateTime?, DateTime?> NullableUtcDateTimeConverter = new(
        value => EnsureUtc(value),
        value => EnsureUtc(value));

    protected SharePasswordDbContext(DbContextOptions options)
        : base(options)
    {
    }

    public DbSet<PasswordShare> PasswordShares => Set<PasswordShare>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<LocalUser> LocalUsers => Set<LocalUser>();
    public DbSet<SystemConfiguration> SystemConfigurations => Set<SystemConfiguration>();
    public DbSet<UsageMetricCounter> UsageMetricCounters => Set<UsageMetricCounter>();
    public DbSet<UsageMetricEvent> UsageMetricEvents => Set<UsageMetricEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var shares = modelBuilder.Entity<PasswordShare>();
        shares.ToTable("PasswordShares");
        shares.HasKey(x => x.Id);
        shares.Property(x => x.RecipientEmail).IsRequired().HasMaxLength(256);
        shares.Property(x => x.SharedUsername).IsRequired().HasMaxLength(256);
        shares.Property(x => x.EncryptedPassword).IsRequired();
        shares.Property(x => x.Instructions).HasMaxLength(1000);
        shares.Property(x => x.AccessCodeHash).IsRequired().HasMaxLength(128);
        shares.Property(x => x.AccessToken).IsRequired().HasMaxLength(64);
        shares.Property(x => x.CreatedAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        shares.Property(x => x.ExpiresAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        shares.Property(x => x.LastAccessedAtUtc).HasConversion(NullableUtcDateTimeConverter);
        shares.Property(x => x.CreatedBy).IsRequired().HasMaxLength(256);
        shares.Property(x => x.RequireOidcLogin).IsRequired();
        shares.Property(x => x.FailedAccessAttempts).IsRequired();
        shares.Property(x => x.AccessPausedUntilUtc).HasConversion(NullableUtcDateTimeConverter);
        shares.HasIndex(x => x.AccessToken).IsUnique();
        shares.HasIndex(x => x.CreatedBy);
        shares.HasIndex(x => x.ExpiresAtUtc);

        var auditLogs = modelBuilder.Entity<AuditLog>();
        auditLogs.ToTable("AuditLogs");
        auditLogs.HasKey(x => x.Id);
        auditLogs.Property(x => x.Id).ValueGeneratedOnAdd();
        auditLogs.Property(x => x.TimestampUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        auditLogs.Property(x => x.ActorType).IsRequired().HasMaxLength(32);
        auditLogs.Property(x => x.ActorIdentifier).IsRequired().HasMaxLength(256);
        auditLogs.Property(x => x.Operation).IsRequired().HasMaxLength(128);
        auditLogs.Property(x => x.TargetType).HasMaxLength(128);
        auditLogs.Property(x => x.TargetId).HasMaxLength(128);
        auditLogs.Property(x => x.IpAddress).HasMaxLength(64);
        auditLogs.Property(x => x.UserAgent).HasMaxLength(1024);
        auditLogs.Property(x => x.CorrelationId).HasMaxLength(128);
        auditLogs.Property(x => x.Details).HasMaxLength(2048);
        auditLogs.HasIndex(x => x.Operation);
        auditLogs.HasIndex(x => x.TimestampUtc);

        var localUsers = modelBuilder.Entity<LocalUser>();
        localUsers.ToTable("LocalUsers");
        localUsers.HasKey(x => x.Id);
        localUsers.Property(x => x.Username).IsRequired().HasMaxLength(128);
        localUsers.Property(x => x.DisplayName).IsRequired().HasMaxLength(256);
        localUsers.Property(x => x.Email).HasMaxLength(256);
        localUsers.Property(x => x.PasswordHash).IsRequired().HasMaxLength(512);
        localUsers.Property(x => x.Roles).IsRequired().HasMaxLength(512);
        localUsers.Property(x => x.IsTotpRequired).IsRequired();
        localUsers.Property(x => x.TotpSecretEncrypted).HasMaxLength(512);
        localUsers.Property(x => x.TotpConfirmedAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.Property(x => x.PendingTotpSecretEncrypted).HasMaxLength(512);
        localUsers.Property(x => x.PendingTotpCreatedAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.Property(x => x.LastTotpResetAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.Property(x => x.CreatedAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        localUsers.Property(x => x.UpdatedAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        localUsers.Property(x => x.LastLoginAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.Property(x => x.LastShareCreatedAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.Property(x => x.LastPasswordResetAtUtc).HasConversion(NullableUtcDateTimeConverter);
        localUsers.HasIndex(x => x.Username).IsUnique();
        localUsers.HasIndex(x => x.Email);

        var systemConfigurations = modelBuilder.Entity<SystemConfiguration>();
        systemConfigurations.ToTable("SystemConfigurations");
        systemConfigurations.HasKey(x => x.Id);
        systemConfigurations.Property(x => x.Id).ValueGeneratedNever();
        systemConfigurations.Property(x => x.TimeZoneId).IsRequired().HasMaxLength(128);
        systemConfigurations.Property(x => x.SmtpHost).HasMaxLength(256);
        systemConfigurations.Property(x => x.SmtpUsername).HasMaxLength(256);
        systemConfigurations.Property(x => x.SmtpPassword).HasMaxLength(512);
        systemConfigurations.Property(x => x.SenderEmail).HasMaxLength(256);
        systemConfigurations.Property(x => x.SenderDisplayName).HasMaxLength(256);
        systemConfigurations.Property(x => x.AdminNotificationRecipients).HasMaxLength(1024);
        systemConfigurations.Property(x => x.ShareAccessedSubjectTemplate).HasMaxLength(512);
        systemConfigurations.Property(x => x.ShareAccessedBodyTemplate).HasMaxLength(4000);
        systemConfigurations.Property(x => x.ShareAccessFailedAttemptLimit).IsRequired();
        systemConfigurations.Property(x => x.ShareAccessPauseMinutes).IsRequired();
        systemConfigurations.Property(x => x.UpdatedAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        systemConfigurations.Property(x => x.UpdatedBy).IsRequired().HasMaxLength(256);

        var usageMetricCounters = modelBuilder.Entity<UsageMetricCounter>();
        usageMetricCounters.ToTable("UsageMetricCounters");
        usageMetricCounters.HasKey(x => x.Key);
        usageMetricCounters.Property(x => x.Key).HasMaxLength(128);
        usageMetricCounters.Property(x => x.UpdatedAtUtc).IsRequired().HasConversion(UtcDateTimeConverter);

        var usageMetricEvents = modelBuilder.Entity<UsageMetricEvent>();
        usageMetricEvents.ToTable("UsageMetricEvents");
        usageMetricEvents.HasKey(x => x.Id);
        usageMetricEvents.Property(x => x.Id).ValueGeneratedOnAdd();
        usageMetricEvents.Property(x => x.TimestampUtc).IsRequired().HasConversion(UtcDateTimeConverter);
        usageMetricEvents.Property(x => x.MetricKey).IsRequired().HasMaxLength(128);
        usageMetricEvents.Property(x => x.ActorType).IsRequired().HasMaxLength(32);
        usageMetricEvents.Property(x => x.ActorIdentifier).IsRequired().HasMaxLength(256);
        usageMetricEvents.Property(x => x.RelatedId).HasMaxLength(128);
        usageMetricEvents.Property(x => x.Details).HasMaxLength(2048);
        usageMetricEvents.HasIndex(x => x.MetricKey);
        usageMetricEvents.HasIndex(x => x.TimestampUtc);
    }

    private static DateTime EnsureUtc(DateTime value)
    {
        if (value == default)
        {
            return value;
        }

        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
    }

    private static DateTime? EnsureUtc(DateTime? value)
    {
        return value is null ? null : EnsureUtc(value.Value);
    }
}

public sealed class SqliteSharePasswordDbContext : SharePasswordDbContext
{
    public SqliteSharePasswordDbContext(DbContextOptions<SqliteSharePasswordDbContext> options)
        : base(options)
    {
    }
}

public sealed class SqlServerSharePasswordDbContext : SharePasswordDbContext
{
    public SqlServerSharePasswordDbContext(DbContextOptions<SqlServerSharePasswordDbContext> options)
        : base(options)
    {
    }
}

public sealed class PostgresqlSharePasswordDbContext : SharePasswordDbContext
{
    public PostgresqlSharePasswordDbContext(DbContextOptions<PostgresqlSharePasswordDbContext> options)
        : base(options)
    {
    }
}
