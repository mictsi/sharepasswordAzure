namespace SharePassword.ViewModels;

public class ProfileViewModel
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    public bool IsLocalAccount { get; set; }
    public DateTime? LastLoginAtUtc { get; set; }
    public DateTime? LastShareCreatedAtUtc { get; set; }
    public DateTime? LastPasswordResetAtUtc { get; set; }
    public int TotalSuccessfulLogins { get; set; }
    public int TotalSharesCreated { get; set; }
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public string? StatusMessage { get; set; }
}