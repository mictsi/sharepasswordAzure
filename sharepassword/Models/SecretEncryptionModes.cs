namespace SharePassword.Models;

public static class SecretEncryptionModes
{
    public const string ServerManaged = "server-managed";
    public const string ClientAesGcm = "client-aes-gcm";
    public const int MaxLength = 32;

    public static bool IsClientEncrypted(string? value)
    {
        return string.Equals(Normalize(value), ClientAesGcm, StringComparison.Ordinal);
    }

    public static string Normalize(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();

        return string.Equals(normalized, ClientAesGcm, StringComparison.Ordinal)
            ? ClientAesGcm
            : ServerManaged;
    }
}
