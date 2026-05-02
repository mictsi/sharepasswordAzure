using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class TotpSetupViewModel
{
    public string Username { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
    public string ProvisioningUri { get; set; } = string.Empty;
    public string QrCodeSvg { get; set; } = string.Empty;
    public bool IsConfirmed { get; set; }
    public bool IsReplacingExistingSetup { get; set; }
    public bool IsPendingLogin { get; set; }
    public string? StatusMessage { get; set; }

    [Display(Name = "Authenticator code")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Authenticator code must be 6 digits.")]
    [RegularExpression("^[0-9]{6}$", ErrorMessage = "Authenticator code must be 6 digits.")]
    public string Code { get; set; } = string.Empty;
}

public class TotpVerificationViewModel
{
    public string Username { get; set; } = string.Empty;

    [Display(Name = "Authenticator code")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Authenticator code must be 6 digits.")]
    [RegularExpression("^[0-9]{6}$", ErrorMessage = "Authenticator code must be 6 digits.")]
    public string Code { get; set; } = string.Empty;
}
