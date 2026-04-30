using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharePassword.Data;
using SharePassword.Models;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class DbSystemConfigurationService : ISystemConfigurationService
{
    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IDatabaseOperationRunner _databaseOperationRunner;
    private readonly ApplicationOptions _applicationOptions;
    private readonly MailOptions _mailOptions;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string _currentTimeZoneId;

    public DbSystemConfigurationService(
        ISharePasswordDbContextFactory dbContextFactory,
        IDatabaseOperationRunner databaseOperationRunner,
        IOptions<ApplicationOptions> applicationOptions,
        IOptions<MailOptions> mailOptions)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
        _applicationOptions = applicationOptions.Value;
        _mailOptions = mailOptions.Value;
        _currentTimeZoneId = NormalizeTimeZoneId(_applicationOptions.TimeZoneId);
    }

    public bool IsSupported => true;

    public string GetCurrentTimeZoneId() => _currentTimeZoneId;

    public TimeZoneInfo GetCurrentTimeZone() => ApplicationOptions.ResolveTimeZone(_currentTimeZoneId);

    public async Task<SystemConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default)
    {
        return await _databaseOperationRunner.ExecuteAsync(
            "load system configuration",
            DatabaseOperationPurpose.Read,
            EnsureConfigurationAsync,
            cancellationToken);
    }

    public async Task<SystemConfiguration> UpdateMailConfigurationAsync(MailConfigurationUpdateRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        return await _databaseOperationRunner.ExecuteAsync(
            "update mail configuration",
            DatabaseOperationPurpose.Write,
            async innerCancellationToken =>
            {
                await _gate.WaitAsync(innerCancellationToken);
                try
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var configuration = await dbContext.SystemConfigurations.SingleOrDefaultAsync(x => x.Id == 1, innerCancellationToken)
                        ?? CreateDefaultConfiguration();

                    configuration.SmtpHost = Trim(request.SmtpHost, 256);
                    configuration.SmtpPort = Math.Clamp(request.SmtpPort, 1, 65535);
                    configuration.SmtpUsername = Trim(request.SmtpUsername, 256);
                    configuration.SmtpPassword = Trim(request.SmtpPassword, 512);
                    configuration.UseTls = request.UseTls;
                    configuration.SenderEmail = Trim(request.SenderEmail, 256);
                    configuration.SenderDisplayName = Trim(request.SenderDisplayName, 256);
                    configuration.AdminNotificationRecipients = Trim(request.AdminNotificationRecipients, 1024);
                    configuration.NotifyAdminsOnShareAccess = request.NotifyAdminsOnShareAccess;
                    configuration.NotifyCreatorOnShareAccess = request.NotifyCreatorOnShareAccess;
                    configuration.ShareAccessedSubjectTemplate = Trim(request.ShareAccessedSubjectTemplate, 512);
                    configuration.ShareAccessedBodyTemplate = Trim(request.ShareAccessedBodyTemplate, 4000);
                    configuration.UpdatedAtUtc = DateTime.UtcNow;
                    configuration.UpdatedBy = Trim(actorIdentifier, 256);

                    if (dbContext.Entry(configuration).State == EntityState.Detached)
                    {
                        dbContext.SystemConfigurations.Add(configuration);
                    }

                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    return Clone(configuration);
                }
                finally
                {
                    _gate.Release();
                }
            },
            cancellationToken);
    }

    public async Task<SystemConfiguration> UpdateTimeZoneAsync(string timeZoneId, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedTimeZoneId = NormalizeTimeZoneId(timeZoneId);
        if (!ApplicationOptions.IsValidTimeZoneId(normalizedTimeZoneId))
        {
            throw new TimeZoneNotFoundException($"Time zone '{normalizedTimeZoneId}' is not available on this host.");
        }

        return await _databaseOperationRunner.ExecuteAsync(
            "update application time zone",
            DatabaseOperationPurpose.Write,
            async innerCancellationToken =>
            {
                await _gate.WaitAsync(innerCancellationToken);
                try
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var configuration = await dbContext.SystemConfigurations.SingleOrDefaultAsync(x => x.Id == 1, innerCancellationToken)
                        ?? CreateDefaultConfiguration();

                    configuration.TimeZoneId = normalizedTimeZoneId;
                    configuration.UpdatedAtUtc = DateTime.UtcNow;
                    configuration.UpdatedBy = Trim(actorIdentifier, 256);

                    if (dbContext.Entry(configuration).State == EntityState.Detached)
                    {
                        dbContext.SystemConfigurations.Add(configuration);
                    }

                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    _currentTimeZoneId = normalizedTimeZoneId;
                    return Clone(configuration);
                }
                finally
                {
                    _gate.Release();
                }
            },
            cancellationToken);
    }

    private async Task<SystemConfiguration> EnsureConfigurationAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            var configuration = await dbContext.SystemConfigurations.SingleOrDefaultAsync(x => x.Id == 1, cancellationToken);
            var shouldSave = false;

            if (configuration is null)
            {
                configuration = CreateDefaultConfiguration();
                dbContext.SystemConfigurations.Add(configuration);
                shouldSave = true;
            }
            else
            {
                shouldSave = ApplyDefaultValues(configuration);
            }

            if (shouldSave)
            {
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            _currentTimeZoneId = NormalizeTimeZoneId(configuration.TimeZoneId);
            return Clone(configuration);
        }
        finally
        {
            _gate.Release();
        }
    }

    private SystemConfiguration CreateDefaultConfiguration()
    {
        return new SystemConfiguration
        {
            Id = 1,
            TimeZoneId = NormalizeTimeZoneId(_applicationOptions.TimeZoneId),
            SmtpHost = Trim(_mailOptions.SmtpHost, 256),
            SmtpPort = Math.Clamp(_mailOptions.Port, 1, 65535),
            SmtpUsername = Trim(_mailOptions.Username, 256),
            SmtpPassword = Trim(_mailOptions.Password, 512),
            UseTls = _mailOptions.UseTls,
            SenderEmail = Trim(_mailOptions.SenderEmail, 256),
            SenderDisplayName = Trim(_mailOptions.SenderDisplayName, 256),
            AdminNotificationRecipients = Trim(_mailOptions.AdminNotificationRecipients, 1024),
            NotifyAdminsOnShareAccess = _mailOptions.NotifyAdminsOnShareAccess,
            NotifyCreatorOnShareAccess = _mailOptions.NotifyCreatorOnShareAccess,
            ShareAccessedSubjectTemplate = Trim(_mailOptions.ShareAccessedSubjectTemplate, 512),
            ShareAccessedBodyTemplate = Trim(_mailOptions.ShareAccessedBodyTemplate, 4000),
            UpdatedAtUtc = DateTime.UtcNow,
            UpdatedBy = "configuration"
        };
    }

    private bool ApplyDefaultValues(SystemConfiguration configuration)
    {
        var changed = false;

        var normalizedTimeZoneId = NormalizeTimeZoneId(_applicationOptions.TimeZoneId);
        if (string.IsNullOrWhiteSpace(configuration.TimeZoneId))
        {
            configuration.TimeZoneId = normalizedTimeZoneId;
            changed = true;
        }

        var defaultSubjectTemplate = Trim(_mailOptions.ShareAccessedSubjectTemplate, 512);
        if (string.IsNullOrWhiteSpace(configuration.ShareAccessedSubjectTemplate))
        {
            configuration.ShareAccessedSubjectTemplate = defaultSubjectTemplate;
            changed = true;
        }

        var defaultBodyTemplate = Trim(_mailOptions.ShareAccessedBodyTemplate, 4000);
        if (string.IsNullOrWhiteSpace(configuration.ShareAccessedBodyTemplate))
        {
            configuration.ShareAccessedBodyTemplate = defaultBodyTemplate;
            changed = true;
        }

        if (configuration.SmtpPort <= 0)
        {
            configuration.SmtpPort = Math.Clamp(_mailOptions.Port, 1, 65535);
            changed = true;
        }

        return changed;
    }

    private static string NormalizeTimeZoneId(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "UTC" : value.Trim();
    }

    private static string Trim(string? value, int maxLength)
    {
        var normalized = (value ?? string.Empty).Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    private static SystemConfiguration Clone(SystemConfiguration source)
    {
        return new SystemConfiguration
        {
            Id = source.Id,
            TimeZoneId = source.TimeZoneId,
            SmtpHost = source.SmtpHost,
            SmtpPort = source.SmtpPort,
            SmtpUsername = source.SmtpUsername,
            SmtpPassword = source.SmtpPassword,
            UseTls = source.UseTls,
            SenderEmail = source.SenderEmail,
            SenderDisplayName = source.SenderDisplayName,
            AdminNotificationRecipients = source.AdminNotificationRecipients,
            NotifyAdminsOnShareAccess = source.NotifyAdminsOnShareAccess,
            NotifyCreatorOnShareAccess = source.NotifyCreatorOnShareAccess,
            ShareAccessedSubjectTemplate = source.ShareAccessedSubjectTemplate,
            ShareAccessedBodyTemplate = source.ShareAccessedBodyTemplate,
            UpdatedAtUtc = source.UpdatedAtUtc,
            UpdatedBy = source.UpdatedBy
        };
    }
}