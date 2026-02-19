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
}
