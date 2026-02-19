namespace SharePassword.Models;

public class AuditLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string ActorType { get; set; } = string.Empty;
    public string ActorIdentifier { get; set; } = string.Empty;
    public string Operation { get; set; } = string.Empty;
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public bool Success { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? CorrelationId { get; set; }
    public string? Details { get; set; }
}
