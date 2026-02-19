namespace SharePassword.Options;

public class ShareOptions
{
    public const string SectionName = "Share";

    public int DefaultExpiryHours { get; set; } = 4;
    public int CleanupIntervalSeconds { get; set; } = 60;
}
