using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public class PasswordCryptoService : IPasswordCryptoService
{
    private readonly string _passphrase;

    public PasswordCryptoService(IOptions<EncryptionOptions> options)
    {
        _passphrase = options.Value.Passphrase;

        if (string.IsNullOrWhiteSpace(_passphrase))
        {
            throw new InvalidOperationException("Encryption passphrase is not configured.");
        }
    }

    public string Encrypt(string plainText)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = DeriveKey(salt);
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, tagSizeInBytes: 16);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        var payload = new byte[salt.Length + nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(salt, 0, payload, 0, salt.Length);
        Buffer.BlockCopy(nonce, 0, payload, salt.Length, nonce.Length);
        Buffer.BlockCopy(tag, 0, payload, salt.Length + nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, salt.Length + nonce.Length + tag.Length, cipherBytes.Length);

        return Convert.ToBase64String(payload);
    }

    public string Decrypt(string cipherText)
    {
        var payload = Convert.FromBase64String(cipherText);

        if (payload.Length < 44)
        {
            throw new InvalidOperationException("Invalid encrypted payload.");
        }

        var salt = payload[..16];
        var nonce = payload[16..28];
        var tag = payload[28..44];
        var cipherBytes = payload[44..];
        var key = DeriveKey(salt);
        var plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(key, tagSizeInBytes: 16);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    private byte[] DeriveKey(byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(_passphrase, salt, 100_000, HashAlgorithmName.SHA256, 32);
    }
}
