namespace SharePassword.Options;

public class MailOptions
{
    public const string SectionName = "Mail";

    public string SmtpHost { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool UseTls { get; set; } = true;
    public string SenderEmail { get; set; } = string.Empty;
    public string SenderDisplayName { get; set; } = "SharePassword";
    public string AdminNotificationRecipients { get; set; } = string.Empty;
    public bool NotifyAdminsOnShareAccess { get; set; } = true;
    public bool NotifyCreatorOnShareAccess { get; set; } = true;
    public string ShareAccessedSubjectTemplate { get; set; } = "Share used: {{SharedUsername}} for {{RecipientEmail}}";
    public string ShareAccessedBodyTemplate { get; set; } = "A secure share has been used.\n\nShare ID: {{ShareId}}\nCreated by: {{CreatedBy}}\nRecipient: {{RecipientEmail}}\nShared username: {{SharedUsername}}\nAccessed by: {{AccessedBy}}\nAccessed at: {{AccessedAt}}\nExpires at: {{ExpiresAt}}\nTime zone: {{TimeZoneId}}";
}