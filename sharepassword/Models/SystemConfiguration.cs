namespace SharePassword.Models;

public class SystemConfiguration
{
    public int Id { get; set; } = 1;
    public string TimeZoneId { get; set; } = "UTC";
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPassword { get; set; } = string.Empty;
    public bool UseTls { get; set; } = true;
    public string SenderEmail { get; set; } = string.Empty;
    public string SenderDisplayName { get; set; } = "SharePassword";
    public string AdminNotificationRecipients { get; set; } = string.Empty;
    public bool NotifyAdminsOnShareAccess { get; set; } = true;
    public bool NotifyCreatorOnShareAccess { get; set; } = true;
    public string ShareAccessedSubjectTemplate { get; set; } = string.Empty;
    public string ShareAccessedBodyTemplate { get; set; } = string.Empty;
    public int ShareAccessFailedAttemptLimit { get; set; } = 5;
    public int ShareAccessPauseMinutes { get; set; } = 15;
    public DateTime UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
}
