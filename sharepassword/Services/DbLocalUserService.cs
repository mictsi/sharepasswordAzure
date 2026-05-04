using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharePassword.Data;
using SharePassword.Models;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class DbLocalUserService : ILocalUserService
{
    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IDatabaseOperationRunner _databaseOperationRunner;
    private readonly IPasswordCryptoService _passwordCryptoService;
    private readonly ITotpService _totpService;
    private readonly ILogger<DbLocalUserService> _logger;
    private readonly IReadOnlyList<string> _availableRoles;
    private readonly string _adminRoleName;
    private readonly string _userRoleName;

    public DbLocalUserService(
        ISharePasswordDbContextFactory dbContextFactory,
        IOptions<OidcAuthOptions> oidcOptions,
        IDatabaseOperationRunner databaseOperationRunner,
        IPasswordCryptoService passwordCryptoService,
        ITotpService totpService,
        ILogger<DbLocalUserService> logger)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
        _passwordCryptoService = passwordCryptoService;
        _totpService = totpService;
        _logger = logger;

        var options = oidcOptions.Value;
        _adminRoleName = string.IsNullOrWhiteSpace(options.AdminRoleName) ? "Admin" : options.AdminRoleName.Trim();
        _userRoleName = string.IsNullOrWhiteSpace(options.UserRoleName) ? "User" : options.UserRoleName.Trim();
        _availableRoles = BuiltInRoleNames.GetAvailableRoles(_adminRoleName, _userRoleName);
    }

    public bool IsSupported => true;

    public IReadOnlyList<string> GetAvailableRoles() => _availableRoles;

    public async Task EnsureBuiltInAdminAsync(string username, string passwordHash, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(username);
        if (string.IsNullOrWhiteSpace(normalizedUsername) || string.IsNullOrWhiteSpace(passwordHash))
        {
            return;
        }

        await ExecuteWriteAsync(
            "ensure built-in admin account",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var existing = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Username == normalizedUsername, innerCancellationToken);
                var now = DateTime.UtcNow;
                var roles = SerializeRoles(NormalizeRoles([_adminRoleName, _userRoleName]));

                if (existing is null)
                {
                    dbContext.LocalUsers.Add(new LocalUser
                    {
                        Id = Guid.NewGuid(),
                        Username = normalizedUsername,
                        DisplayName = normalizedUsername,
                        Email = string.Empty,
                        PasswordHash = passwordHash.Trim(),
                        Roles = roles,
                        IsDisabled = false,
                        IsSeededAdmin = true,
                        IsTotpRequired = false,
                        CreatedAtUtc = now,
                        UpdatedAtUtc = now,
                        LastPasswordResetAtUtc = now
                    });
                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    return;
                }

                if (!existing.IsSeededAdmin)
                {
                    return;
                }

                existing.PasswordHash = passwordHash.Trim();
                existing.Roles = roles;
                existing.IsDisabled = false;
                existing.UpdatedAtUtc = now;
                existing.LastPasswordResetAtUtc = now;
                await dbContext.SaveChangesAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task EnsureTotpSecretsEncryptedAsync(CancellationToken cancellationToken = default)
    {
        await ExecuteWriteAsync(
            "ensure local user totp secrets are encrypted",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var users = await dbContext.LocalUsers
                    .Where(x => x.TotpSecretEncrypted != string.Empty || x.PendingTotpSecretEncrypted != string.Empty)
                    .ToListAsync(innerCancellationToken);

                var updatedSecretCount = 0;
                var now = DateTime.UtcNow;

                foreach (var user in users)
                {
                    if (TryEncryptPlaintextTotpSecret(user.TotpSecretEncrypted, out var encryptedTotpSecret))
                    {
                        user.TotpSecretEncrypted = encryptedTotpSecret;
                        user.UpdatedAtUtc = now;
                        updatedSecretCount++;
                    }

                    if (TryEncryptPlaintextTotpSecret(user.PendingTotpSecretEncrypted, out var encryptedPendingTotpSecret))
                    {
                        user.PendingTotpSecretEncrypted = encryptedPendingTotpSecret;
                        user.UpdatedAtUtc = now;
                        updatedSecretCount++;
                    }
                }

                if (updatedSecretCount == 0)
                {
                    return;
                }

                await dbContext.SaveChangesAsync(innerCancellationToken);
                _logger.LogInformation("Encrypted {TotpSecretCount} legacy local user TOTP secret value(s) at rest.", updatedSecretCount);
            },
            cancellationToken);
    }

    public async Task<LocalUserAuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(username);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return LocalUserAuthenticationResult.Failed("Invalid login attempt.");
        }

        try
        {
            return await ExecuteWriteAsync(
                "authenticate local user",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers
                        .SingleOrDefaultAsync(x => x.Username == normalizedUsername, innerCancellationToken);

                    if (user is null || user.IsDisabled)
                    {
                        return LocalUserAuthenticationResult.Failed("Invalid login attempt.");
                    }

                    if (!AdminPasswordHash.Verify(password, user.PasswordHash))
                    {
                        return LocalUserAuthenticationResult.Failed("Invalid login attempt.");
                    }

                    if (AdminPasswordHash.NeedsUpgrade(user.PasswordHash))
                    {
                        user.PasswordHash = AdminPasswordHash.Create(password);
                        user.UpdatedAtUtc = DateTime.UtcNow;
                        await dbContext.SaveChangesAsync(innerCancellationToken);
                    }

                    return LocalUserAuthenticationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserAuthenticationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<IReadOnlyCollection<LocalUser>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await ExecuteReadAsync(
            "load local users",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var users = await dbContext.LocalUsers
                    .AsNoTracking()
                    .OrderBy(x => x.Username)
                    .ToListAsync(innerCancellationToken);

                return users.Select(Clone).ToList();
            },
            cancellationToken);
    }

    public async Task<LocalUser?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await ExecuteReadAsync(
            "load local user by id",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var user = await dbContext.LocalUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                return user is null ? null : Clone(user);
            },
            cancellationToken);
    }

    public async Task<LocalUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(username);
        return await ExecuteReadAsync(
            "load local user by username",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var user = await dbContext.LocalUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Username == normalizedUsername, innerCancellationToken);
                return user is null ? null : Clone(user);
            },
            cancellationToken);
    }

    public async Task<LocalUserMutationResult> CreateAsync(LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(request.Username);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return LocalUserMutationResult.Failed("Username is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            return LocalUserMutationResult.Failed("A password is required when creating a local user.");
        }

        var passwordValidationErrors = LocalUserPasswordPolicy.Validate(request.Password);
        if (passwordValidationErrors.Count > 0)
        {
            return LocalUserMutationResult.Failed(passwordValidationErrors[0]);
        }

        var normalizedRoles = NormalizeRoles(request.Roles);
        if (normalizedRoles.Count == 0)
        {
            return LocalUserMutationResult.Failed("At least one built-in role must be selected.");
        }

        try
        {
            return await ExecuteWriteAsync(
                "create local user",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var existing = await dbContext.LocalUsers.AnyAsync(x => x.Username == normalizedUsername, innerCancellationToken);
                    if (existing)
                    {
                        return LocalUserMutationResult.Failed("That username is already in use.");
                    }

                    var now = DateTime.UtcNow;
                    var user = new LocalUser
                    {
                        Id = Guid.NewGuid(),
                        Username = normalizedUsername,
                        DisplayName = NormalizeDisplayName(request.DisplayName, normalizedUsername),
                        Email = NormalizeEmail(request.Email),
                        PasswordHash = AdminPasswordHash.Create(request.Password),
                        Roles = SerializeRoles(normalizedRoles),
                        IsDisabled = request.IsDisabled,
                        IsTotpRequired = request.IsTotpRequired,
                        CreatedAtUtc = now,
                        UpdatedAtUtc = now,
                        LastPasswordResetAtUtc = now,
                        IsSeededAdmin = false
                    };

                    dbContext.LocalUsers.Add(user);
                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserMutationResult> UpdateAsync(Guid id, LocalUserUpsertRequest request, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(request.Username);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return LocalUserMutationResult.Failed("Username is required.");
        }

        var normalizedRoles = NormalizeRoles(request.Roles);
        if (normalizedRoles.Count == 0)
        {
            return LocalUserMutationResult.Failed("At least one built-in role must be selected.");
        }

        try
        {
            return await ExecuteWriteAsync(
                "update local user",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    var duplicate = await dbContext.LocalUsers.AnyAsync(x => x.Id != id && x.Username == normalizedUsername, innerCancellationToken);
                    if (duplicate)
                    {
                        return LocalUserMutationResult.Failed("That username is already in use.");
                    }

                    if (await WouldRemoveLastEnabledAdminAsync(dbContext, user, normalizedRoles, request.IsDisabled, innerCancellationToken))
                    {
                        return LocalUserMutationResult.Failed("At least one enabled administrator must remain available.");
                    }

                    user.Username = normalizedUsername;
                    user.DisplayName = NormalizeDisplayName(request.DisplayName, normalizedUsername);
                    user.Email = NormalizeEmail(request.Email);
                    user.Roles = SerializeRoles(normalizedRoles);
                    user.IsDisabled = request.IsDisabled;
                    user.IsTotpRequired = request.IsTotpRequired;
                    user.UpdatedAtUtc = DateTime.UtcNow;

                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserMutationResult> DeleteAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        try
        {
            return await ExecuteWriteAsync(
                "delete local user",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    if (await WouldRemoveLastEnabledAdminAsync(dbContext, user, Array.Empty<string>(), true, innerCancellationToken))
                    {
                        return LocalUserMutationResult.Failed("At least one enabled administrator must remain available.");
                    }

                    dbContext.LocalUsers.Remove(user);
                    await dbContext.SaveChangesAsync(innerCancellationToken);
                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserMutationResult> ResetPasswordAsync(Guid id, string newPassword, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return LocalUserMutationResult.Failed("A new password is required.");
        }

        var passwordValidationErrors = LocalUserPasswordPolicy.Validate(newPassword);
        if (passwordValidationErrors.Count > 0)
        {
            return LocalUserMutationResult.Failed(passwordValidationErrors[0]);
        }

        try
        {
            return await ExecuteWriteAsync(
                "reset local user password",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    user.PasswordHash = AdminPasswordHash.Create(newPassword);
                    user.LastPasswordResetAtUtc = DateTime.UtcNow;
                    user.UpdatedAtUtc = DateTime.UtcNow;
                    await dbContext.SaveChangesAsync(innerCancellationToken);

                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserMutationResult> ChangeOwnPasswordAsync(Guid id, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return LocalUserMutationResult.Failed("A new password is required.");
        }

        var passwordValidationErrors = LocalUserPasswordPolicy.Validate(newPassword);
        if (passwordValidationErrors.Count > 0)
        {
            return LocalUserMutationResult.Failed(passwordValidationErrors[0]);
        }

        try
        {
            return await ExecuteWriteAsync(
                "change local user password",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    if (!AdminPasswordHash.Verify(currentPassword, user.PasswordHash))
                    {
                        return LocalUserMutationResult.Failed("The current password is incorrect.");
                    }

                    user.PasswordHash = AdminPasswordHash.Create(newPassword);
                    user.LastPasswordResetAtUtc = DateTime.UtcNow;
                    user.UpdatedAtUtc = DateTime.UtcNow;
                    await dbContext.SaveChangesAsync(innerCancellationToken);

                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserTotpSetupResult> EnsureTotpSetupAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        try
        {
            return await ExecuteWriteAsync(
                "ensure local user totp setup",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserTotpSetupResult.Failed("The selected user could not be found.");
                    }

                    var secretKey = string.IsNullOrWhiteSpace(user.PendingTotpSecretEncrypted)
                        ? _totpService.GenerateSecretKey()
                        : _passwordCryptoService.Decrypt(user.PendingTotpSecretEncrypted);

                    if (string.IsNullOrWhiteSpace(user.PendingTotpSecretEncrypted))
                    {
                        user.PendingTotpSecretEncrypted = _passwordCryptoService.Encrypt(secretKey);
                        user.PendingTotpCreatedAtUtc = DateTime.UtcNow;
                        user.UpdatedAtUtc = DateTime.UtcNow;
                        await dbContext.SaveChangesAsync(innerCancellationToken);
                    }

                    return LocalUserTotpSetupResult.Success(Clone(user), _totpService.BuildSetup(secretKey, GetTotpAccountName(user)));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserTotpSetupResult.Failed(exception.UserMessage);
        }
    }

    public async Task<LocalUserMutationResult> ConfirmTotpAsync(Guid id, string code, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        return await VerifyTotpCoreAsync(id, code, requireConfirmedSecret: false, confirmSetup: true, cancellationToken);
    }

    public async Task<LocalUserMutationResult> VerifyTotpAsync(Guid id, string code, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        return await VerifyTotpCoreAsync(id, code, requireConfirmedSecret: true, confirmSetup: false, cancellationToken);
    }

    public async Task<LocalUserMutationResult> RemoveTotpAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        try
        {
            return await ExecuteWriteAsync(
                "remove local user totp",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    user.TotpSecretEncrypted = string.Empty;
                    user.TotpConfirmedAtUtc = null;
                    user.LastTotpTimeStepMatched = null;
                    user.PendingTotpSecretEncrypted = string.Empty;
                    user.PendingTotpCreatedAtUtc = null;
                    user.LastTotpResetAtUtc = DateTime.UtcNow;
                    user.UpdatedAtUtc = DateTime.UtcNow;
                    await dbContext.SaveChangesAsync(innerCancellationToken);

                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    public async Task RecordSuccessfulLoginAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await ExecuteBestEffortWriteAsync(
            "record local user login statistics",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                if (user is null)
                {
                    return;
                }

                user.LastLoginAtUtc = DateTime.UtcNow;
                user.TotalSuccessfulLogins += 1;
                user.UpdatedAtUtc = DateTime.UtcNow;
                await dbContext.SaveChangesAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task RecordShareCreatedAsync(string actorIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(actorIdentifier);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return;
        }

        await ExecuteBestEffortWriteAsync(
            "record local user share statistics",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Username == normalizedUsername, innerCancellationToken);
                if (user is null)
                {
                    return;
                }

                user.TotalSharesCreated += 1;
                user.LastShareCreatedAtUtc = DateTime.UtcNow;
                user.UpdatedAtUtc = DateTime.UtcNow;
                await dbContext.SaveChangesAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task<string?> ResolveEmailAsync(string actorIdentifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(actorIdentifier))
        {
            return null;
        }

        if (actorIdentifier.Contains('@', StringComparison.Ordinal))
        {
            return actorIdentifier.Trim().ToLowerInvariant();
        }

        var normalizedUsername = NormalizeUsername(actorIdentifier);
        return await ExecuteReadAsync(
            "resolve local user email",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                return await dbContext.LocalUsers
                    .Where(x => x.Username == normalizedUsername)
                    .Select(x => x.Email)
                    .SingleOrDefaultAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    private Task<T> ExecuteReadAsync<T>(string operationName, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        return _databaseOperationRunner.ExecuteAsync(operationName, DatabaseOperationPurpose.Read, operation, cancellationToken);
    }

    private Task ExecuteWriteAsync(string operationName, Func<CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        return _databaseOperationRunner.ExecuteAsync(operationName, DatabaseOperationPurpose.Write, operation, cancellationToken);
    }

    private Task<T> ExecuteWriteAsync<T>(string operationName, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        return _databaseOperationRunner.ExecuteAsync(operationName, DatabaseOperationPurpose.Write, operation, cancellationToken);
    }

    private async Task ExecuteBestEffortWriteAsync(string operationName, Func<CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        try
        {
            await ExecuteWriteAsync(operationName, operation, cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            _logger.LogWarning(exception, "Best-effort local user database operation {OperationName} failed. {DiagnosticMessage}", operationName, exception.DiagnosticMessage);
        }
    }

    private async Task<LocalUserMutationResult> VerifyTotpCoreAsync(Guid id, string code, bool requireConfirmedSecret, bool confirmSetup, CancellationToken cancellationToken)
    {
        try
        {
            return await ExecuteWriteAsync(
                confirmSetup ? "confirm local user totp" : "verify local user totp",
                async innerCancellationToken =>
                {
                    await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);
                    var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
                    if (user is null)
                    {
                        return LocalUserMutationResult.Failed("The selected user could not be found.");
                    }

                    var secretKey = GetTotpSecretForVerification(user, requireConfirmedSecret, confirmSetup, out var lastTimeStepMatched, out var errorMessage);
                    if (secretKey is null)
                    {
                        return LocalUserMutationResult.Failed(errorMessage ?? "Authenticator app setup is required.");
                    }

                    if (!_totpService.VerifyCode(secretKey, code, lastTimeStepMatched, out var timeStepMatched))
                    {
                        return LocalUserMutationResult.Failed("Invalid authenticator code.");
                    }

                    if (confirmSetup)
                    {
                        user.TotpSecretEncrypted = user.PendingTotpSecretEncrypted;
                        user.TotpConfirmedAtUtc = DateTime.UtcNow;
                        user.PendingTotpSecretEncrypted = string.Empty;
                        user.PendingTotpCreatedAtUtc = null;
                    }

                    user.LastTotpTimeStepMatched = timeStepMatched;
                    user.UpdatedAtUtc = DateTime.UtcNow;
                    await dbContext.SaveChangesAsync(innerCancellationToken);

                    return LocalUserMutationResult.Success(Clone(user));
                },
                cancellationToken);
        }
        catch (DatabaseOperationException exception)
        {
            return LocalUserMutationResult.Failed(exception.UserMessage);
        }
    }

    private async Task<bool> WouldRemoveLastEnabledAdminAsync(SharePasswordDbContext dbContext, LocalUser user, IReadOnlyCollection<string> resultingRoles, bool resultingDisabled, CancellationToken cancellationToken)
    {
        var currentRoles = ParseRoles(user.Roles);
        var currentlyEnabledAdmin = !user.IsDisabled && currentRoles.Contains(_adminRoleName, StringComparer.OrdinalIgnoreCase);
        var stillEnabledAdmin = !resultingDisabled && resultingRoles.Contains(_adminRoleName, StringComparer.OrdinalIgnoreCase);

        if (!currentlyEnabledAdmin || stillEnabledAdmin)
        {
            return false;
        }

        var users = await dbContext.LocalUsers.AsNoTracking().ToListAsync(cancellationToken);
        var enabledAdminCount = users.Count(candidate => !candidate.IsDisabled && ParseRoles(candidate.Roles).Contains(_adminRoleName, StringComparer.OrdinalIgnoreCase));
        return enabledAdminCount <= 1;
    }

    private IReadOnlyCollection<string> NormalizeRoles(IEnumerable<string> roles)
    {
        var availableRoles = GetAvailableRoles();
        var normalized = roles
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Where(role => availableRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (normalized.Contains(_adminRoleName, StringComparer.OrdinalIgnoreCase)
            && !normalized.Contains(_userRoleName, StringComparer.OrdinalIgnoreCase))
        {
            normalized.Add(_userRoleName);
        }

        return normalized;
    }

    private static IReadOnlyCollection<string> ParseRoles(string? roles)
    {
        return (roles ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string SerializeRoles(IReadOnlyCollection<string> roles)
    {
        return string.Join(';', roles.OrderBy(role => role, StringComparer.OrdinalIgnoreCase));
    }

    private static string NormalizeUsername(string? username)
    {
        return string.IsNullOrWhiteSpace(username) ? string.Empty : username.Trim().ToLowerInvariant();
    }

    private static string NormalizeDisplayName(string? displayName, string fallbackUsername)
    {
        var normalized = (displayName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return fallbackUsername;
        }

        return normalized.Length <= 256 ? normalized : normalized[..256];
    }

    private static string NormalizeEmail(string? email)
    {
        var normalized = string.IsNullOrWhiteSpace(email) ? string.Empty : email.Trim().ToLowerInvariant();
        return normalized.Length <= 256 ? normalized : normalized[..256];
    }

    private static string GetTotpAccountName(LocalUser user)
    {
        return string.IsNullOrWhiteSpace(user.Email) ? user.Username : user.Email;
    }

    private string? GetTotpSecretForVerification(LocalUser user, bool requireConfirmedSecret, bool confirmSetup, out long? lastTimeStepMatched, out string? errorMessage)
    {
        lastTimeStepMatched = user.LastTotpTimeStepMatched;
        errorMessage = null;

        if (confirmSetup)
        {
            if (string.IsNullOrWhiteSpace(user.PendingTotpSecretEncrypted))
            {
                errorMessage = "Authenticator app setup is required.";
                return null;
            }

            lastTimeStepMatched = null;
            return _passwordCryptoService.Decrypt(user.PendingTotpSecretEncrypted);
        }

        if (string.IsNullOrWhiteSpace(user.TotpSecretEncrypted))
        {
            errorMessage = "Authenticator app setup is required.";
            return null;
        }

        if (requireConfirmedSecret && user.TotpConfirmedAtUtc is null)
        {
            errorMessage = "Authenticator app setup must be confirmed before sign-in.";
            return null;
        }

        return _passwordCryptoService.Decrypt(user.TotpSecretEncrypted);
    }

    private bool TryEncryptPlaintextTotpSecret(string storedValue, out string encryptedValue)
    {
        encryptedValue = storedValue;

        if (string.IsNullOrWhiteSpace(storedValue) || CanDecrypt(storedValue))
        {
            return false;
        }

        var normalizedSecret = NormalizeTotpSecretCandidate(storedValue);
        if (!LooksLikePlaintextTotpSecret(normalizedSecret))
        {
            return false;
        }

        encryptedValue = _passwordCryptoService.Encrypt(normalizedSecret);
        return true;
    }

    private bool CanDecrypt(string storedValue)
    {
        try
        {
            _passwordCryptoService.Decrypt(storedValue);
            return true;
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or InvalidOperationException)
        {
            return false;
        }
    }

    private static string NormalizeTotpSecretCandidate(string storedValue)
    {
        return storedValue.Trim().Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
    }

    private static bool LooksLikePlaintextTotpSecret(string value)
    {
        return value.Length is >= 16 and <= 128
            && value.All(character => character is >= 'A' and <= 'Z' or >= '2' and <= '7');
    }

    private static LocalUser Clone(LocalUser source)
    {
        return new LocalUser
        {
            Id = source.Id,
            Username = source.Username,
            DisplayName = source.DisplayName,
            Email = source.Email,
            PasswordHash = source.PasswordHash,
            Roles = source.Roles,
            IsDisabled = source.IsDisabled,
            IsSeededAdmin = source.IsSeededAdmin,
            IsTotpRequired = source.IsTotpRequired,
            TotpSecretEncrypted = source.TotpSecretEncrypted,
            TotpConfirmedAtUtc = source.TotpConfirmedAtUtc,
            LastTotpTimeStepMatched = source.LastTotpTimeStepMatched,
            PendingTotpSecretEncrypted = source.PendingTotpSecretEncrypted,
            PendingTotpCreatedAtUtc = source.PendingTotpCreatedAtUtc,
            LastTotpResetAtUtc = source.LastTotpResetAtUtc,
            CreatedAtUtc = source.CreatedAtUtc,
            UpdatedAtUtc = source.UpdatedAtUtc,
            LastLoginAtUtc = source.LastLoginAtUtc,
            LastShareCreatedAtUtc = source.LastShareCreatedAtUtc,
            LastPasswordResetAtUtc = source.LastPasswordResetAtUtc,
            TotalSuccessfulLogins = source.TotalSuccessfulLogins,
            TotalSharesCreated = source.TotalSharesCreated
        };
    }
}
