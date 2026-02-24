using Microsoft.Extensions.Options;
using SharePassword.Options;
using SharePassword.Services;

namespace SharePassword.Tests;

public class PasswordCryptoServiceTests
{
    private static PasswordCryptoService CreateService()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new EncryptionOptions
        {
            Passphrase = "unit-test-passphrase-1234567890"
        });

        return new PasswordCryptoService(options);
    }

    [Fact]
    public void EncryptThenDecrypt_ReturnsOriginalValue()
    {
        var service = CreateService();
        const string plain = "P@ssw0rd!";

        var encrypted = service.Encrypt(plain);
        var decrypted = service.Decrypt(encrypted);

        Assert.Equal(plain, decrypted);
    }

    [Fact]
    public void Encrypt_SameInputTwice_ProducesDifferentCiphertext()
    {
        var service = CreateService();
        const string plain = "same-input";

        var encrypted1 = service.Encrypt(plain);
        var encrypted2 = service.Encrypt(plain);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void EncryptThenDecrypt_PreservesMultilineAndSpecialCharacters()
    {
        var service = CreateService();
        var prefix = "plain text line 1\nline 2 with symbols !@#$%^&*()[]{}<>\\\"'\n---\nkey: value\nlist:\n  - one\n  - two\n{\"json\":true,\"count\":2}\n";
        var fillerLength = 1000 - prefix.Length;
        var plain = prefix + new string('x', fillerLength);

        Assert.Equal(1000, plain.Length);

        var encrypted = service.Encrypt(plain);
        var decrypted = service.Decrypt(encrypted);

        Assert.Equal(plain, decrypted);
    }
}
