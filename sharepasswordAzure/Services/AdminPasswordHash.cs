using System.Security.Cryptography;

namespace SharePassword.Services;

public static class AdminPasswordHash
{
    public static bool IsValid(string passwordHash)
    {
        return TryParse(passwordHash, out _, out _, out _);
    }

    public static bool Verify(string password, string passwordHash)
    {
        if (!TryParse(passwordHash, out var iterations, out var salt, out var expectedHash))
        {
            return false;
        }

        var actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private static bool TryParse(string passwordHash, out int iterations, out byte[] salt, out byte[] expectedHash)
    {
        iterations = 0;
        salt = Array.Empty<byte>();
        expectedHash = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            return false;
        }

        var parts = passwordHash.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 || !string.Equals(parts[0], "PBKDF2", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(parts[1], "SHA256", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!int.TryParse(parts[2], out iterations) || iterations <= 0)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expectedHash = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length > 0 && expectedHash.Length > 0;
    }
}