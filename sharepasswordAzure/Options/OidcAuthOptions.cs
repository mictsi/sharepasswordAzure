namespace SharePassword.Options;

public class OidcAuthOptions
{
    public const string SectionName = "OidcAuth";

    public bool Enabled { get; set; } = false;
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public bool RequireHttpsMetadata { get; set; } = true;
    public string[] Scopes { get; set; } = ["openid", "profile", "email"];
    public string GroupClaimType { get; set; } = "groups";
    public string AdminRoleName { get; set; } = "Admin";
    public string UserRoleName { get; set; } = "User";
    public string[] AdminGroups { get; set; } = [];
    public string[] UserGroups { get; set; } = [];
}
