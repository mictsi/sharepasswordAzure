namespace SharePassword.ViewModels;

public class ShareCredentialViewModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}
