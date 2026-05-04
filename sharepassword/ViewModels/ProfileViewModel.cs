using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class ProfileViewModel
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    public bool IsLocalAccount { get; set; }
    public bool IsTotpRequired { get; set; }
    public bool IsTotpConfigured { get; set; }
    public DateTime? LastLoginAtUtc { get; set; }
    public DateTime? LastShareCreatedAtUtc { get; set; }
    public DateTime? LastPasswordResetAtUtc { get; set; }
    public int TotalSuccessfulLogins { get; set; }
    public int TotalSharesCreated { get; set; }
    [Display(Name = "Current password")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Display(Name = "New password")]
    public string NewPassword { get; set; } = string.Empty;

    [Display(Name = "Confirm password")]
    public string ConfirmPassword { get; set; } = string.Empty;
    public string? StatusMessage { get; set; }
}
