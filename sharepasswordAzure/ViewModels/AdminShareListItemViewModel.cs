namespace SharePassword.ViewModels;

public class AdminShareListItemViewModel
{
    public Guid Id { get; set; }
    public string RecipientEmail { get; set; } = string.Empty;
    public string SharedUsername { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public bool IsExpired { get; set; }
    public bool RequireOidcLogin { get; set; }
}
