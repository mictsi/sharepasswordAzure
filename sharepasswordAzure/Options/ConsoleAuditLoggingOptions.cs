namespace SharePassword.Options;

public class ConsoleAuditLoggingOptions
{
    public const string SectionName = "ConsoleAuditLogging";

    public bool Enabled { get; set; } = false;
    public string Level { get; set; } = "INFO";
}
