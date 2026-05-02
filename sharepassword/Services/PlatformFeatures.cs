using SharePassword.Models;

namespace SharePassword.Services;

public static class BuiltInRoleNames
{
    public const string Auditor = "Auditor";

    public static IReadOnlyList<string> GetAvailableRoles(string adminRoleName, string userRoleName)
    {
        var roles = new List<string>();

        AddIfMissing(userRoleName);
        AddIfMissing(adminRoleName);
        AddIfMissing(Auditor);

        return roles;

        void AddIfMissing(string? role)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                return;
            }

            var normalized = role.Trim();
            if (!roles.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                roles.Add(normalized);
            }
        }
    }
}

public interface ITimeZoneSettingsProvider
{
    string GetCurrentTimeZoneId();
    TimeZoneInfo GetCurrentTimeZone();
}

public interface ISystemConfigurationService : ITimeZoneSettingsProvider
{
    bool IsSupported { get; }
    Task<SystemConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default);
    Task<SystemConfiguration> UpdateMailConfigurationAsync(MailConfigurationUpdateRequest request, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<SystemConfiguration> UpdateTimeZoneAsync(string timeZoneId, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<SystemConfiguration> UpdateApplicationSettingsAsync(ApplicationSettingsUpdateRequest request, string actorIdentifier, CancellationToken cancellationToken = default);
}

public interface ILocalUserService
{
    bool IsSupported { get; }
    IReadOnlyList<string> GetAvailableRoles();
    Task EnsureBuiltInAdminAsync(string username, string passwordHash, CancellationToken cancellationToken = default);
    Task<LocalUserAuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<IReadOnlyCollection<LocalUser>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<LocalUser?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<LocalUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> CreateAsync(LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> UpdateAsync(Guid id, LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> DeleteAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> ResetPasswordAsync(Guid id, string newPassword, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> ChangeOwnPasswordAsync(Guid id, string currentPassword, string newPassword, CancellationToken cancellationToken = default);
    Task<LocalUserTotpSetupResult> EnsureTotpSetupAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> ConfirmTotpAsync(Guid id, string code, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> VerifyTotpAsync(Guid id, string code, string actorIdentifier, CancellationToken cancellationToken = default);
    Task<LocalUserMutationResult> RemoveTotpAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default);
    Task RecordSuccessfulLoginAsync(Guid id, CancellationToken cancellationToken = default);
    Task RecordShareCreatedAsync(string actorIdentifier, CancellationToken cancellationToken = default);
    Task<string?> ResolveEmailAsync(string actorIdentifier, CancellationToken cancellationToken = default);
}

public interface IUsageMetricsService
{
    bool IsSupported { get; }
    Task RecordAsync(string metricKey, string actorType, string actorIdentifier, long increment = 1, string? relatedId = null, string? details = null, CancellationToken cancellationToken = default);
    Task<DashboardMetricsSnapshot> GetDashboardSnapshotAsync(CancellationToken cancellationToken = default);
}

public interface INotificationEmailService
{
    Task NotifyShareAccessedAsync(PasswordShare share, string accessedByIdentifier, CancellationToken cancellationToken = default);
}

public interface IPlatformInitializationService
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
}

public sealed class MailConfigurationUpdateRequest
{
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPassword { get; set; } = string.Empty;
    public bool UseTls { get; set; } = true;
    public string SenderEmail { get; set; } = string.Empty;
    public string SenderDisplayName { get; set; } = string.Empty;
    public string AdminNotificationRecipients { get; set; } = string.Empty;
    public bool NotifyAdminsOnShareAccess { get; set; } = true;
    public bool NotifyCreatorOnShareAccess { get; set; } = true;
    public string ShareAccessedSubjectTemplate { get; set; } = string.Empty;
    public string ShareAccessedBodyTemplate { get; set; } = string.Empty;
}

public sealed class ApplicationSettingsUpdateRequest
{
    public string TimeZoneId { get; set; } = "UTC";
    public int ShareAccessFailedAttemptLimit { get; set; } = 5;
    public int ShareAccessPauseMinutes { get; set; } = 15;
}

public sealed class LocalUserUpsertRequest
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    public string? Password { get; set; }
    public bool IsDisabled { get; set; }
    public bool IsTotpRequired { get; set; }
}

public sealed class LocalUserAuthenticationResult
{
    private LocalUserAuthenticationResult(bool succeeded, LocalUser? user, string? errorMessage)
    {
        Succeeded = succeeded;
        User = user;
        ErrorMessage = errorMessage;
    }

    public bool Succeeded { get; }
    public LocalUser? User { get; }
    public string? ErrorMessage { get; }

    public static LocalUserAuthenticationResult Success(LocalUser user) => new(true, user, null);
    public static LocalUserAuthenticationResult Failed(string errorMessage) => new(false, null, errorMessage);
}

public sealed class LocalUserMutationResult
{
    private LocalUserMutationResult(bool succeeded, LocalUser? user, string? errorMessage)
    {
        Succeeded = succeeded;
        User = user;
        ErrorMessage = errorMessage;
    }

    public bool Succeeded { get; }
    public LocalUser? User { get; }
    public string? ErrorMessage { get; }

    public static LocalUserMutationResult Success(LocalUser user) => new(true, user, null);
    public static LocalUserMutationResult Failed(string errorMessage) => new(false, null, errorMessage);
}

public sealed class LocalUserTotpSetupResult
{
    private LocalUserTotpSetupResult(bool succeeded, LocalUser? user, TotpSetupDetails? setup, string? errorMessage)
    {
        Succeeded = succeeded;
        User = user;
        Setup = setup;
        ErrorMessage = errorMessage;
    }

    public bool Succeeded { get; }
    public LocalUser? User { get; }
    public TotpSetupDetails? Setup { get; }
    public string? ErrorMessage { get; }

    public static LocalUserTotpSetupResult Success(LocalUser user, TotpSetupDetails setup) => new(true, user, setup, null);
    public static LocalUserTotpSetupResult Failed(string errorMessage) => new(false, null, null, errorMessage);
}

public sealed class TotpSetupDetails
{
    public string SecretKey { get; init; } = string.Empty;
    public string ProvisioningUri { get; init; } = string.Empty;
    public string QrCodeSvg { get; init; } = string.Empty;
}

public sealed class DashboardMetricsSnapshot
{
    public long TotalSharesCreated { get; init; }
    public long TotalShareAccesses { get; init; }
    public long AdminLogins { get; init; }
    public long UserLogins { get; init; }
    public long ExpiredSharesDeleted { get; init; }
    public long ExpiredUnusedSharesDeleted { get; init; }
}
