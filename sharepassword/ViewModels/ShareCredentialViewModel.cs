using SharePassword.Models;

namespace SharePassword.ViewModels;

public class ShareCredentialViewModel
{
    public Guid ShareId { get; set; }
    public string RecipientEmail { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string SecretEncryptionMode { get; set; } = SecretEncryptionModes.ServerManaged;
    public string Instructions { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }

    public bool IsClientEncrypted => SecretEncryptionModes.IsClientEncrypted(SecretEncryptionMode);
}
