namespace SharePassword.ViewModels;

public class LocalUserEditorViewModel
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public IReadOnlyCollection<string> AvailableRoles { get; set; } = Array.Empty<string>();
    public string[] SelectedRoles { get; set; } = [];
    public bool IsDisabled { get; set; }
    public bool IsSeededAdmin { get; set; }
    public bool IsTotpRequired { get; set; }
    public bool IsTotpConfigured { get; set; }
    public DateTime? LastLoginAtUtc { get; set; }
    public DateTime? LastShareCreatedAtUtc { get; set; }
    public DateTime? LastPasswordResetAtUtc { get; set; }
    public int TotalSuccessfulLogins { get; set; }
    public int TotalSharesCreated { get; set; }
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public LocalUserPasswordResetViewModel? ResetPassword { get; set; }
    public string? StatusMessage { get; set; }

    public bool IsCreateMode => Id == Guid.Empty;
}

public class LocalUserPasswordResetViewModel
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
