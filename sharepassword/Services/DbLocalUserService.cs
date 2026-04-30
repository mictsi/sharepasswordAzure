using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharePassword.Data;
using SharePassword.Models;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class DbLocalUserService : ILocalUserService
{
    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IReadOnlyList<string> _availableRoles;
    private readonly string _adminRoleName;
    private readonly string _userRoleName;

    public DbLocalUserService(ISharePasswordDbContextFactory dbContextFactory, IOptions<OidcAuthOptions> oidcOptions)
    {
        _dbContextFactory = dbContextFactory;

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

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var existing = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Username == normalizedUsername, cancellationToken);
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
            await dbContext.SaveChangesAsync(cancellationToken);
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
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<LocalUserAuthenticationResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(username);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return LocalUserAuthenticationResult.Failed("Invalid login attempt.");
        }

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers
            .SingleOrDefaultAsync(x => x.Username == normalizedUsername, cancellationToken);

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
            await dbContext.SaveChangesAsync(cancellationToken);
        }

        return LocalUserAuthenticationResult.Success(Clone(user));
    }

    public async Task<IReadOnlyCollection<LocalUser>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var users = await dbContext.LocalUsers
            .AsNoTracking()
            .OrderBy(x => x.Username)
            .ToListAsync(cancellationToken);

        return users.Select(Clone).ToList();
    }

    public async Task<LocalUser?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        return user is null ? null : Clone(user);
    }

    public async Task<LocalUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(username);
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Username == normalizedUsername, cancellationToken);
        return user is null ? null : Clone(user);
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

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var existing = await dbContext.LocalUsers.AnyAsync(x => x.Username == normalizedUsername, cancellationToken);
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
        await dbContext.SaveChangesAsync(cancellationToken);
        return LocalUserMutationResult.Success(Clone(user));
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

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (user is null)
        {
            return LocalUserMutationResult.Failed("The selected user could not be found.");
        }

        var duplicate = await dbContext.LocalUsers.AnyAsync(x => x.Id != id && x.Username == normalizedUsername, cancellationToken);
        if (duplicate)
        {
            return LocalUserMutationResult.Failed("That username is already in use.");
        }

        if (await WouldRemoveLastEnabledAdminAsync(dbContext, user, normalizedRoles, request.IsDisabled, cancellationToken))
        {
            return LocalUserMutationResult.Failed("At least one enabled administrator must remain available.");
        }

        user.Username = normalizedUsername;
        user.DisplayName = NormalizeDisplayName(request.DisplayName, normalizedUsername);
        user.Email = NormalizeEmail(request.Email);
        user.Roles = SerializeRoles(normalizedRoles);
        user.IsDisabled = request.IsDisabled;
        user.UpdatedAtUtc = DateTime.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);
        return LocalUserMutationResult.Success(Clone(user));
    }

    public async Task<LocalUserMutationResult> DeleteAsync(Guid id, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (user is null)
        {
            return LocalUserMutationResult.Failed("The selected user could not be found.");
        }

        if (await WouldRemoveLastEnabledAdminAsync(dbContext, user, Array.Empty<string>(), true, cancellationToken))
        {
            return LocalUserMutationResult.Failed("At least one enabled administrator must remain available.");
        }

        dbContext.LocalUsers.Remove(user);
        await dbContext.SaveChangesAsync(cancellationToken);
        return LocalUserMutationResult.Success(Clone(user));
    }

    public async Task<LocalUserMutationResult> ResetPasswordAsync(Guid id, string newPassword, string actorIdentifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return LocalUserMutationResult.Failed("A new password is required.");
        }

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (user is null)
        {
            return LocalUserMutationResult.Failed("The selected user could not be found.");
        }

        user.PasswordHash = AdminPasswordHash.Create(newPassword);
        user.LastPasswordResetAtUtc = DateTime.UtcNow;
        user.UpdatedAtUtc = DateTime.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        return LocalUserMutationResult.Success(Clone(user));
    }

    public async Task<LocalUserMutationResult> ChangeOwnPasswordAsync(Guid id, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return LocalUserMutationResult.Failed("A new password is required.");
        }

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
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
        await dbContext.SaveChangesAsync(cancellationToken);

        return LocalUserMutationResult.Success(Clone(user));
    }

    public async Task RecordSuccessfulLoginAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (user is null)
        {
            return;
        }

        user.LastLoginAtUtc = DateTime.UtcNow;
        user.TotalSuccessfulLogins += 1;
        user.UpdatedAtUtc = DateTime.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RecordShareCreatedAsync(string actorIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedUsername = NormalizeUsername(actorIdentifier);
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            return;
        }

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var user = await dbContext.LocalUsers.SingleOrDefaultAsync(x => x.Username == normalizedUsername, cancellationToken);
        if (user is null)
        {
            return;
        }

        user.TotalSharesCreated += 1;
        user.LastShareCreatedAtUtc = DateTime.UtcNow;
        user.UpdatedAtUtc = DateTime.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
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
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.LocalUsers
            .Where(x => x.Username == normalizedUsername)
            .Select(x => x.Email)
            .SingleOrDefaultAsync(cancellationToken);
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