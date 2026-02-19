using SharePassword.Models;

namespace SharePassword.Services;

public interface IAuditLogSink
{
    Task AddAuditAsync(AuditLog auditLog, CancellationToken cancellationToken = default);
}
