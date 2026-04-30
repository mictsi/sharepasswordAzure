namespace SharePassword.Options;

public class DatabaseResilienceOptions
{
    public const string SectionName = "DatabaseResilience";

    public int MaxAttempts { get; set; } = 3;

    public int DelayMilliseconds { get; set; } = 1000;
}