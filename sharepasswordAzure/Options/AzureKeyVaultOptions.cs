namespace SharePassword.Options;

public class AzureKeyVaultOptions
{
    public const string SectionName = "AzureKeyVault";

    public string VaultUri { get; set; } = string.Empty;
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string SecretPrefix { get; set; } = "sharepassword";
}
