using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class AdminCreateShareViewModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Recipient email")]
    public string RecipientEmail { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Username")]
    public string SharedUsername { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Range(1, 168)]
    [Display(Name = "Expires in (hours)")]
    public int ExpiryHours { get; set; } = 4;

    [Display(Name = "Require Entra ID login to access")]
    public bool RequireOidcLogin { get; set; }
}
