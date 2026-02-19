using SharePassword.Models;

namespace SharePassword.Services;

public interface IAuditLogReader
{
    Task<IReadOnlyCollection<AuditLog>> GetLatestAsync(int take, CancellationToken cancellationToken = default);
}
