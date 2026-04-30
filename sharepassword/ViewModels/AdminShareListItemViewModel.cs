namespace SharePassword.ViewModels;

public class AdminShareListItemViewModel
{
    public Guid Id { get; set; }
    public string RecipientEmail { get; set; } = string.Empty;
    public string SharedUsername { get; set; } = string.Empty;
    public string CreatedBy { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? LastAccessedAtUtc { get; set; }
    public bool IsExpired { get; set; }
    public bool IsExpiringSoon { get; set; }
    public bool RequireOidcLogin { get; set; }

    public bool HasBeenAccessed => LastAccessedAtUtc.HasValue;
    public string AccessModeLabel => RequireOidcLogin ? "Microsoft Entra ID + email + code" : "Email + code";
    public string AccessModeTone => RequireOidcLogin ? "entra" : "standard";
    public string StatusLabel => IsExpired ? "Expired" : IsExpiringSoon ? "Expiring soon" : HasBeenAccessed ? "Accessed" : "Active";
    public string StatusTone => IsExpired ? "expired" : IsExpiringSoon ? "warning" : HasBeenAccessed ? "accessed" : "active";
}
