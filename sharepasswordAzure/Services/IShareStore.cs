using SharePassword.Models;

namespace SharePassword.Services;

public interface IShareStore
{
    Task<IReadOnlyCollection<PasswordShare>> GetAllSharesAsync(CancellationToken cancellationToken = default);
    Task<PasswordShare?> GetShareByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<PasswordShare?> GetShareByTokenAsync(string token, CancellationToken cancellationToken = default);
    Task UpsertShareAsync(PasswordShare share, CancellationToken cancellationToken = default);
    Task DeleteShareAsync(Guid id, CancellationToken cancellationToken = default);
    Task<int> DeleteExpiredSharesAsync(DateTime utcNow, CancellationToken cancellationToken = default);
}
