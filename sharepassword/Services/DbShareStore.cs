using Microsoft.EntityFrameworkCore;
using SharePassword.Data;
using SharePassword.Models;

namespace SharePassword.Services;

public class DbShareStore : IShareStore
{
    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IDatabaseOperationRunner _databaseOperationRunner;

    public DbShareStore(ISharePasswordDbContextFactory dbContextFactory, IDatabaseOperationRunner databaseOperationRunner)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
    }

    public async Task<IReadOnlyCollection<PasswordShare>> GetAllSharesAsync(CancellationToken cancellationToken = default)
    {
        return await ExecuteReadAsync(
            "load password shares",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                return await dbContext.PasswordShares
                    .AsNoTracking()
                    .ToListAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task<PasswordShare?> GetShareByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await ExecuteReadAsync(
            "load password share by id",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                return await dbContext.PasswordShares
                    .AsNoTracking()
                    .SingleOrDefaultAsync(x => x.Id == id, innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task<PasswordShare?> GetShareByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var normalizedToken = NormalizeToken(token);
        return await ExecuteReadAsync(
            "load password share by token",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                return await dbContext.PasswordShares
                    .AsNoTracking()
                    .SingleOrDefaultAsync(x => x.AccessToken == normalizedToken, innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task UpsertShareAsync(PasswordShare share, CancellationToken cancellationToken = default)
    {
        var normalizedShare = CloneShare(share);
        await ExecuteWriteAsync(
            "upsert password share",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                var existing = await dbContext.PasswordShares
                    .SingleOrDefaultAsync(x => x.Id == normalizedShare.Id, innerCancellationToken);

                if (existing is null)
                {
                    dbContext.PasswordShares.Add(normalizedShare);
                }
                else
                {
                    CopyShare(normalizedShare, existing);
                }

                await dbContext.SaveChangesAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task DeleteShareAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await ExecuteWriteAsync(
            "delete password share",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                await dbContext.PasswordShares
                    .Where(x => x.Id == id)
                    .ExecuteDeleteAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    public async Task<int> DeleteExpiredSharesAsync(DateTime utcNow, CancellationToken cancellationToken = default)
    {
        var normalizedUtcNow = EnsureUtc(utcNow);
        return await ExecuteWriteAsync(
            "delete expired password shares",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                return await dbContext.PasswordShares
                    .Where(x => x.ExpiresAtUtc <= normalizedUtcNow)
                    .ExecuteDeleteAsync(innerCancellationToken);
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

    private static PasswordShare CloneShare(PasswordShare share)
    {
        return new PasswordShare
        {
            Id = share.Id,
            RecipientEmail = (share.RecipientEmail ?? string.Empty).Trim().ToLowerInvariant(),
            SharedUsername = share.SharedUsername ?? string.Empty,
            EncryptedPassword = share.EncryptedPassword ?? string.Empty,
            SecretEncryptionMode = SecretEncryptionModes.Normalize(share.SecretEncryptionMode),
            Instructions = share.Instructions ?? string.Empty,
            AccessCodeHash = share.AccessCodeHash ?? string.Empty,
            AccessToken = NormalizeToken(share.AccessToken),
            CreatedAtUtc = EnsureUtc(share.CreatedAtUtc),
            ExpiresAtUtc = EnsureUtc(share.ExpiresAtUtc),
            LastAccessedAtUtc = EnsureUtc(share.LastAccessedAtUtc),
            CreatedBy = share.CreatedBy ?? string.Empty,
            RequireOidcLogin = share.RequireOidcLogin,
            FailedAccessAttempts = Math.Max(0, share.FailedAccessAttempts),
            AccessPausedUntilUtc = EnsureUtc(share.AccessPausedUntilUtc)
        };
    }

    private static void CopyShare(PasswordShare source, PasswordShare target)
    {
        target.RecipientEmail = source.RecipientEmail;
        target.SharedUsername = source.SharedUsername;
        target.EncryptedPassword = source.EncryptedPassword;
        target.SecretEncryptionMode = source.SecretEncryptionMode;
        target.Instructions = source.Instructions;
        target.AccessCodeHash = source.AccessCodeHash;
        target.AccessToken = source.AccessToken;
        target.CreatedAtUtc = source.CreatedAtUtc;
        target.ExpiresAtUtc = source.ExpiresAtUtc;
        target.LastAccessedAtUtc = source.LastAccessedAtUtc;
        target.CreatedBy = source.CreatedBy;
        target.RequireOidcLogin = source.RequireOidcLogin;
        target.FailedAccessAttempts = source.FailedAccessAttempts;
        target.AccessPausedUntilUtc = source.AccessPausedUntilUtc;
    }

    private static string NormalizeToken(string? token)
    {
        return (token ?? string.Empty).Trim().ToLowerInvariant();
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
