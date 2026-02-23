using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class ShareAccessViewModel
{
    [EmailAddress]
    [Display(Name = "Email address")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Access code")]
    public string Code { get; set; } = string.Empty;

    public string Token { get; set; } = string.Empty;
    public bool RequireOidcLogin { get; set; }
}
