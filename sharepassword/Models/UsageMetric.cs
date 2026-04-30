namespace SharePassword.Models;

public class UsageMetricCounter
{
    public string Key { get; set; } = string.Empty;
    public long Count { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

public class UsageMetricEvent
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string MetricKey { get; set; } = string.Empty;
    public string ActorType { get; set; } = string.Empty;
    public string ActorIdentifier { get; set; } = string.Empty;
    public long Increment { get; set; }
    public string? RelatedId { get; set; }
    public string? Details { get; set; }
}