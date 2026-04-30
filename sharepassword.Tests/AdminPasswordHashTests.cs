using System.Security.Cryptography;
using SharePassword.Services;

namespace SharePassword.Tests;

public class AdminPasswordHashTests
{
    [Fact]
    public void Create_ProducesSupportedHash_ThatVerifies()
    {
        const string password = "Admin-Password-For-Hashing-Tests!";

        var hash = AdminPasswordHash.Create(password);

        Assert.True(AdminPasswordHash.IsValid(hash));
        Assert.True(AdminPasswordHash.Verify(password, hash));
        Assert.False(AdminPasswordHash.Verify("wrong-password", hash));
    }

    [Fact]
    public void Verify_SupportsLegacyPbkdf2Hashes()
    {
        const string password = "legacy-password";
        var hash = CreateLegacyPbkdf2Hash(password);

        Assert.True(AdminPasswordHash.IsValid(hash));
        Assert.True(AdminPasswordHash.Verify(password, hash));
        Assert.True(AdminPasswordHash.NeedsUpgrade(hash));
    }

    [Fact]
    public void IsValid_RejectsMalformedHashes()
    {
        Assert.False(AdminPasswordHash.IsValid(string.Empty));
        Assert.False(AdminPasswordHash.IsValid("PBKDF2$SHA256$not-a-number$salt$hash"));
        Assert.False(AdminPasswordHash.IsValid("ARGON2ID$v=19$m=65536,t=3,p=1$not-base64$also-not-base64"));
        Assert.False(AdminPasswordHash.IsValid("SCRYPT$N=32768,r=8,p=1$not-base64$also-not-base64"));
    }

    private static string CreateLegacyPbkdf2Hash(string password, int iterations = 210_000)
    {
        byte[] salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        return $"PBKDF2$SHA256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }
}