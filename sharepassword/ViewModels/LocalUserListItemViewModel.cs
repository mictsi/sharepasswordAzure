namespace SharePassword.ViewModels;

public class LocalUserListItemViewModel
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    public bool IsDisabled { get; set; }
    public bool IsSeededAdmin { get; set; }
    public DateTime? LastLoginAtUtc { get; set; }
    public DateTime? LastShareCreatedAtUtc { get; set; }
    public DateTime? LastPasswordResetAtUtc { get; set; }
    public int TotalSuccessfulLogins { get; set; }
    public int TotalSharesCreated { get; set; }
}