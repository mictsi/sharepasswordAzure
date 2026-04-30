using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class UnsupportedSystemConfigurationService : ISystemConfigurationService
{
    private readonly ApplicationOptions _applicationOptions;
    private readonly MailOptions _mailOptions;

    public UnsupportedSystemConfigurationService(IOptions<ApplicationOptions> applicationOptions, IOptions<MailOptions> mailOptions)
    {
        _applicationOptions = applicationOptions.Value;
        _mailOptions = mailOptions.Value;
    }

    public bool IsSupported => false;

    public string GetCurrentTimeZoneId() => NormalizeTimeZoneId(_applicationOptions.TimeZoneId);

    public TimeZoneInfo GetCurrentTimeZone() => ApplicationOptions.ResolveTimeZone(GetCurrentTimeZoneId());

    public Task<SystemConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new SystemConfiguration
        {
            TimeZoneId = GetCurrentTimeZoneId(),
            SmtpHost = _mailOptions.SmtpHost,
            SmtpPort = _mailOptions.Port,
            SmtpUsername = _mailOptions.Username,
            SmtpPassword = _mailOptions.Password,
            UseTls = _mailOptions.UseTls,
            SenderEmail = _mailOptions.SenderEmail,
            SenderDisplayName = _mailOptions.SenderDisplayName,
            AdminNotificationRecipients = _mailOptions.AdminNotificationRecipients,
            NotifyAdminsOnShareAccess = _mailOptions.NotifyAdminsOnShareAccess,
            NotifyCreatorOnShareAccess = _mailOptions.NotifyCreatorOnShareAccess,
            ShareAccessedSubjectTemplate = _mailOptions.ShareAccessedSubjectTemplate,
            ShareAccessedBodyTemplate = _mailOptions.ShareAccessedBodyTemplate,
            UpdatedAtUtc = DateTime.UtcNow,
            UpdatedBy = "configuration"
        });
    }

    public Task<SystemConfiguration> UpdateMailConfigurationAsync(MailConfigurationUpdateRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("Editable mail configuration is only available for database-backed storage backends.");
    }

    public Task<SystemConfiguration> UpdateTimeZoneAsync(string timeZoneId, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("Editable application settings are only available for database-backed storage backends.");
    }

    private static string NormalizeTimeZoneId(string? timeZoneId)
    {
        return string.IsNullOrWhiteSpace(timeZoneId) ? "UTC" : timeZoneId.Trim();
    }
}

public sealed class UnsupportedLocalUserService : ILocalUserService
{
    private readonly IReadOnlyList<string> _availableRoles;

    public UnsupportedLocalUserService(IOptions<OidcAuthOptions> oidcOptions)
    {
        var options = oidcOptions.Value;
        var adminRoleName = string.IsNullOrWhiteSpace(options.AdminRoleName) ? "Admin" : options.AdminRoleName.Trim();
        var userRoleName = string.IsNullOrWhiteSpace(options.UserRoleName) ? "User" : options.UserRoleName.Trim();
        _availableRoles = BuiltInRoleNames.GetAvailableRoles(adminRoleName, userRoleName);
    }

    public bool IsSupported => false;

    public IReadOnlyList<string> GetAvailableRoles() => _availableRoles;

    public Task EnsureBuiltInAdminAsync(string username, string passwordHash, CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<LocalUserAuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserAuthenticationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task<IReadOnlyCollection<LocalUser>> GetAllAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyCollection<LocalUser>>(Array.Empty<LocalUser>());

    public Task<LocalUser?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        => Task.FromResult<LocalUser?>(null);

    public Task<LocalUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
        => Task.FromResult<LocalUser?>(null);

    public Task<LocalUserMutationResult> CreateAsync(LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserMutationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task<LocalUserMutationResult> UpdateAsync(Guid id, LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserMutationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task<LocalUserMutationResult> DeleteAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserMutationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task<LocalUserMutationResult> ResetPasswordAsync(Guid id, string newPassword, string actorIdentifier, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserMutationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task<LocalUserMutationResult> ChangeOwnPasswordAsync(Guid id, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
        => Task.FromResult(LocalUserMutationResult.Failed("Local user management is only available for database-backed storage backends."));

    public Task RecordSuccessfulLoginAsync(Guid id, CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task RecordShareCreatedAsync(string actorIdentifier, CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<string?> ResolveEmailAsync(string actorIdentifier, CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(ContainsEmail(actorIdentifier) ? actorIdentifier.Trim().ToLowerInvariant() : null);

    private static bool ContainsEmail(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) && value.Contains('@', StringComparison.Ordinal);
    }
}

public sealed class UnsupportedUsageMetricsService : IUsageMetricsService
{
    public bool IsSupported => false;

    public Task RecordAsync(string metricKey, string actorType, string actorIdentifier, long increment = 1, string? relatedId = null, string? details = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<DashboardMetricsSnapshot> GetDashboardSnapshotAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(new DashboardMetricsSnapshot());
}

public sealed class UnsupportedNotificationEmailService : INotificationEmailService
{
    public Task NotifyShareAccessedAsync(PasswordShare share, string accessedByIdentifier, CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}

public sealed class UnsupportedPlatformInitializationService : IPlatformInitializationService
{
    public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}