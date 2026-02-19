namespace SharePassword.Services;

public interface IAuditLogger
{
    Task LogAsync(
        string actorType,
        string actorIdentifier,
        string operation,
        bool success,
        string? targetType = null,
        string? targetId = null,
        string? details = null,
        CancellationToken cancellationToken = default);
}
