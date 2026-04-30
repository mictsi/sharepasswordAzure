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
    private readonly ILogger<DbLocalUserService> _logger;
    private readonly IReadOnlyList<string> _availableRoles;
    private readonly string _adminRoleName;
    private readonly string _userRoleName;

    public DbLocalUserService(
        ISharePasswordDbContextFactory dbContextFactory,
        IOptions<OidcAuthOptions> oidcOptions,
        IDatabaseOperationRunner databaseOperationRunner,
        ILogger<DbLocalUserService> logger)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
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