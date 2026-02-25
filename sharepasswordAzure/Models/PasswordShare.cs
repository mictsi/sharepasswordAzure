namespace SharePassword.Models;

public class PasswordShare
{
    public Guid Id { get; set; }
    public string RecipientEmail { get; set; } = string.Empty;
    public string SharedUsername { get; set; } = string.Empty;
    public string EncryptedPassword { get; set; } = string.Empty;
    public string Instructions { get; set; } = string.Empty;
    public string AccessCodeHash { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? LastAccessedAtUtc { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public bool RequireOidcLogin { get; set; }
}
