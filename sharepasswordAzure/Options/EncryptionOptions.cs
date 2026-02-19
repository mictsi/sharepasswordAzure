namespace SharePassword.Options;

public class EncryptionOptions
{
    public const string SectionName = "Encryption";

    public string Passphrase { get; set; } = "ReplaceWithStrongEncryptionPassphrase";
}
