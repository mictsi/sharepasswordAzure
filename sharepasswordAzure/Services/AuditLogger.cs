using Microsoft.Extensions.Options;
using SharePassword.Options;
using SharePassword.Models;

namespace SharePassword.Services;

public class AuditLogger : IAuditLogger
{
    private readonly IAuditLogSink _auditLogSink;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditLogger> _logger;
    private readonly ConsoleAuditLoggingOptions _consoleAuditLoggingOptions;

    public AuditLogger(
        IAuditLogSink auditLogSink,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditLogger> logger,
        IOptions<ConsoleAuditLoggingOptions> consoleAuditLoggingOptions)
    {
        _auditLogSink = auditLogSink;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _consoleAuditLoggingOptions = consoleAuditLoggingOptions.Value;
    }

    private static string? SanitizeForLogging(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        // Remove line breaks to mitigate log forging in plain-text logs
        return value
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal);
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
        var sanitizedActorType = SanitizeForLogging(actorType) ?? string.Empty;
        var sanitizedActorIdentifier = SanitizeForLogging(actorIdentifier) ?? string.Empty;
        var sanitizedOperation = SanitizeForLogging(operation) ?? string.Empty;
        var sanitizedTargetType = SanitizeForLogging(targetType);
        var sanitizedTargetId = SanitizeForLogging(targetId);
        var sanitizedDetails = SanitizeForLogging(details);
        var sanitizedIpAddress = SanitizeForLogging(context?.Connection.RemoteIpAddress?.ToString());
        var sanitizedUserAgent = SanitizeForLogging(context?.Request.Headers.UserAgent.ToString());
        var sanitizedCorrelationId = SanitizeForLogging(context?.TraceIdentifier);

        var audit = new AuditLog
        {
            TimestampUtc = DateTime.UtcNow,
            ActorType = sanitizedActorType,
            ActorIdentifier = sanitizedActorIdentifier,
            Operation = sanitizedOperation,
            Success = success,
            TargetType = sanitizedTargetType,
            TargetId = sanitizedTargetId,
            Details = sanitizedDetails,
            IpAddress = sanitizedIpAddress,
            UserAgent = sanitizedUserAgent,
            CorrelationId = sanitizedCorrelationId
        };

        await _auditLogSink.AddAuditAsync(audit, cancellationToken);

        if (!_consoleAuditLoggingOptions.Enabled)
        {
            return;
        }

        var configuredLevel = (_consoleAuditLoggingOptions.Level ?? "INFO").Trim().ToUpperInvariant();
        var message = "Audit event: Operation={Operation}, Success={Success}, ActorType={ActorType}, Actor={Actor}, TargetType={TargetType}, TargetId={TargetId}, CorrelationId={CorrelationId}, Details={Details}";

        if (!success)
        {
            _logger.LogError(
                message,
                sanitizedOperation,
                success,
                sanitizedActorType,
                sanitizedActorIdentifier,
                sanitizedTargetType,
                sanitizedTargetId,
                sanitizedCorrelationId,
                sanitizedDetails);

            return;
        }

        if (configuredLevel == "ERROR")
        {
            return;
        }

        if (configuredLevel == "DEBUG")
        {
            _logger.LogDebug(
                message,
                sanitizedOperation,
                success,
                sanitizedActorType,
                sanitizedActorIdentifier,
                sanitizedTargetType,
                sanitizedTargetId,
                sanitizedCorrelationId,
                sanitizedDetails);
            return;
        }

        _logger.LogInformation(
            message,
            sanitizedOperation,
            success,
            sanitizedActorType,
            sanitizedActorIdentifier,
            sanitizedTargetType,
            sanitizedTargetId,
            sanitizedCorrelationId,
            sanitizedDetails);
    }
}
