using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class AdminCreateShareViewModel
{
    [Required]
    [EmailAddress]
    [StringLength(256, ErrorMessage = "Recipient email cannot exceed 256 characters.")]
    [Display(Name = "Recipient email")]
    public string RecipientEmail { get; set; } = string.Empty;

    [Required]
    [StringLength(256, ErrorMessage = "Username cannot exceed 256 characters.")]
    [Display(Name = "Username")]
    public string SharedUsername { get; set; } = string.Empty;

    [Required]
    [StringLength(1000, ErrorMessage = "Secret text cannot exceed 1000 characters.")]
    [DataType(DataType.MultilineText)]
    [Display(Name = "Secret text")]
    public string Password { get; set; } = string.Empty;

    [StringLength(1000, ErrorMessage = "Instructions cannot exceed 1000 characters.")]
    [DataType(DataType.MultilineText)]
    [Display(Name = "Instructions")]
    public string Instructions { get; set; } = string.Empty;

    [Range(1, 168)]
    [Display(Name = "Expires in (hours)")]
    public int ExpiryHours { get; set; } = 4;

    [Display(Name = "Require Entra ID login to access")]
    public bool RequireOidcLogin { get; set; }
}
