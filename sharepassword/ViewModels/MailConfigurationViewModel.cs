namespace SharePassword.ViewModels;

public class MailConfigurationViewModel
{
    public bool IsSupported { get; set; }
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPassword { get; set; } = string.Empty;
    public bool UseTls { get; set; } = true;
    public string SenderEmail { get; set; } = string.Empty;
    public string SenderDisplayName { get; set; } = string.Empty;
    public string AdminNotificationRecipients { get; set; } = string.Empty;
    public bool NotifyAdminsOnShareAccess { get; set; } = true;
    public bool NotifyCreatorOnShareAccess { get; set; } = true;
    public string ShareAccessedSubjectTemplate { get; set; } = string.Empty;
    public string ShareAccessedBodyTemplate { get; set; } = string.Empty;
    public string? StatusMessage { get; set; }
}