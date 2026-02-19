using SharePassword.Models;

namespace SharePassword.Services;

public class AuditLogger : IAuditLogger
{
    private readonly IAuditLogSink _auditLogSink;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuditLogger(
        IAuditLogSink auditLogSink,
        IHttpContextAccessor httpContextAccessor)
    {
        _auditLogSink = auditLogSink;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task LogAsync(
        string actorType,
        string actorIdentifier,
        string operation,
        bool success,
        string? targetType = null,
        string? targetId = null,
        string? details = null,
        CancellationToken cancellationToken = default)
    {
        var context = _httpContextAccessor.HttpContext;

        var audit = new AuditLog
        {
            TimestampUtc = DateTime.UtcNow,
            ActorType = actorType,
            ActorIdentifier = actorIdentifier,
            Operation = operation,
            Success = success,
            TargetType = targetType,
            TargetId = targetId,
            Details = details,
            IpAddress = context?.Connection.RemoteIpAddress?.ToString(),
            UserAgent = context?.Request.Headers.UserAgent.ToString(),
            CorrelationId = context?.TraceIdentifier
        };

        await _auditLogSink.AddAuditAsync(audit, cancellationToken);
    }
}
