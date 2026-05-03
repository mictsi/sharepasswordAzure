using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharePassword.Models;

public sealed class ClientEncryptedSecretPayload
{
    public const int Version = 1;
    public const int KdfIterations = 310_000;
    public const int MaxPayloadLength = 12_000;
    public const string AlgorithmName = "AES-256-GCM";
    public const string KdfName = "PBKDF2-SHA256";

    [JsonPropertyName("version")]
    public int PayloadVersion { get; set; }

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("kdf")]
    public string Kdf { get; set; } = string.Empty;

    [JsonPropertyName("iterations")]
    public int Iterations { get; set; }

    [JsonPropertyName("salt")]
    public string Salt { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    public static bool TryValidate(string payload, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(payload))
        {
            errorMessage = "The browser-encrypted secret payload is required.";
            return false;
        }

        if (payload.Length > MaxPayloadLength)
        {
            errorMessage = "The browser-encrypted secret payload is too large.";
            return false;
        }

        ClientEncryptedSecretPayload? encryptedPayload;
        try
        {
            encryptedPayload = JsonSerializer.Deserialize<ClientEncryptedSecretPayload>(payload);
        }
        catch (JsonException)
        {
            errorMessage = "The browser-encrypted secret payload is not valid JSON.";
            return false;
        }

        if (encryptedPayload is null)
        {
            errorMessage = "The browser-encrypted secret payload is invalid.";
            return false;
        }

        if (encryptedPayload.PayloadVersion != Version)
        {
            errorMessage = "The browser-encrypted secret payload version is unsupported.";
            return false;
        }

        if (!string.Equals(encryptedPayload.Algorithm, AlgorithmName, StringComparison.Ordinal))
        {
            errorMessage = "The browser-encrypted secret algorithm is unsupported.";
            return false;
        }

        if (!string.Equals(encryptedPayload.Kdf, KdfName, StringComparison.Ordinal))
        {
            errorMessage = "The browser-encrypted secret key derivation is unsupported.";
            return false;
        }

        if (encryptedPayload.Iterations != KdfIterations)
        {
            errorMessage = "The browser-encrypted secret key derivation settings are unsupported.";
            return false;
        }

        if (!HasBase64ByteLength(encryptedPayload.Salt, expectedLength: 16))
        {
            errorMessage = "The browser-encrypted secret salt is invalid.";
            return false;
        }

        if (!HasBase64ByteLength(encryptedPayload.Nonce, expectedLength: 12))
        {
            errorMessage = "The browser-encrypted secret nonce is invalid.";
            return false;
        }

        if (!HasCiphertext(encryptedPayload.Ciphertext))
        {
            errorMessage = "The browser-encrypted secret ciphertext is invalid.";
            return false;
        }

        return true;
    }

    private static bool HasBase64ByteLength(string value, int expectedLength)
    {
        return TryDecodeBase64(value, out var decoded) && decoded.Length == expectedLength;
    }

    private static bool HasCiphertext(string value)
    {
        if (!TryDecodeBase64(value, out var decoded))
        {
            return false;
        }

        return decoded.Length is > 16 and <= 8192;
    }

    private static bool TryDecodeBase64(string value, out byte[] decoded)
    {
        decoded = [];

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            decoded = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
