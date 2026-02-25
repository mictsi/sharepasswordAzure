using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class ShareAccessViewModel
{
    [EmailAddress]
    [StringLength(256, ErrorMessage = "Email address cannot exceed 256 characters.")]
    [Display(Name = "Email address")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(8, MinimumLength = 8, ErrorMessage = "Access code must be exactly 8 characters.")]
    [RegularExpression("^[A-Za-z0-9]{8}$", ErrorMessage = "Access code format is invalid.")]
    [Display(Name = "Access code")]
    public string Code { get; set; } = string.Empty;

    [Required]
    [StringLength(32, MinimumLength = 32, ErrorMessage = "Invalid link token format.")]
    [RegularExpression("^[A-Fa-f0-9]{32}$", ErrorMessage = "Invalid link token format.")]
    public string Token { get; set; } = string.Empty;
    public bool RequireOidcLogin { get; set; }
}
