namespace SharePassword.Options;

public class AdminAuthOptions
{
    public const string SectionName = "AdminAuth";

    public string Username { get; set; } = "admin";
    public string PasswordHash { get; set; } = string.Empty;
}
