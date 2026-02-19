namespace SharePassword.ViewModels;

public class AdminShareCreatedViewModel
{
    public Guid ShareId { get; set; }
    public string RecipientEmail { get; set; } = string.Empty;
    public string ShareLink { get; set; } = string.Empty;
    public string AccessCode { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}
