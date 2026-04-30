using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;

namespace SharePassword.Services;

public static class AdminPasswordHash
{
    private const string Argon2idAlgorithmName = "ARGON2ID";
    private const string ScryptAlgorithmName = "SCRYPT";
    private const string LegacyPbkdf2AlgorithmName = "PBKDF2";
    private const string LegacyPbkdf2HashAlgorithmName = "SHA256";
    private const int CurrentArgon2Version = 19;
    private const int DefaultSaltSizeBytes = 16;
    private const int DefaultHashSizeBytes = 32;
    private const int DefaultArgon2MemorySizeKiB = 65_536;
    private const int DefaultArgon2Iterations = 3;
    private const int DefaultArgon2Parallelism = 1;
    private const int DefaultScryptCost = 32_768;
    private const int DefaultScryptBlockSize = 8;
    private const int DefaultScryptParallelism = 1;

    public static string Create(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (TryCreateArgon2id(password, out var passwordHash))
        {
            return passwordHash;
        }

        return CreateScrypt(password);
    }

    public static bool IsValid(string passwordHash)
    {
        return TryParse(passwordHash, out _);
    }

    public static bool Verify(string password, string passwordHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (!TryParse(passwordHash, out var parsedHash))
        {
            return false;
        }

        byte[] actualHash;
        try
        {
            actualHash = parsedHash.Algorithm switch
            {
                AdminPasswordHashAlgorithm.Argon2id => DeriveArgon2idBytes(password, parsedHash.Salt, parsedHash.Cost1, parsedHash.Cost2, parsedHash.Cost3, parsedHash.ExpectedHash.Length),
                AdminPasswordHashAlgorithm.Scrypt => DeriveScryptBytes(password, parsedHash.Salt, parsedHash.Cost1, parsedHash.Cost2, parsedHash.Cost3, parsedHash.ExpectedHash.Length),
                AdminPasswordHashAlgorithm.LegacyPbkdf2 => DeriveLegacyPbkdf2Bytes(password, parsedHash.Salt, parsedHash.Cost1, parsedHash.ExpectedHash.Length),
                _ => Array.Empty<byte>()
            };
        }
        catch (Exception ex) when (parsedHash.Algorithm == AdminPasswordHashAlgorithm.Argon2id && IsArgon2idUnavailable(ex))
        {
            return false;
        }

        var expectedHash = parsedHash.ExpectedHash;
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    public static bool NeedsUpgrade(string passwordHash)
    {
        if (!TryParse(passwordHash, out var parsedHash))
        {
            return false;
        }

        return parsedHash.Algorithm switch
        {
            AdminPasswordHashAlgorithm.LegacyPbkdf2 => true,
            AdminPasswordHashAlgorithm.Scrypt => IsArgon2idAvailable(),
            _ => false
        };
    }

    private static bool TryCreateArgon2id(string password, out string passwordHash)
    {
        passwordHash = string.Empty;

        try
        {
            var salt = CreateSalt();
            var hash = DeriveArgon2idBytes(password, salt, DefaultArgon2MemorySizeKiB, DefaultArgon2Iterations, DefaultArgon2Parallelism, DefaultHashSizeBytes);
            passwordHash = $"{Argon2idAlgorithmName}$v={CurrentArgon2Version}$m={DefaultArgon2MemorySizeKiB},t={DefaultArgon2Iterations},p={DefaultArgon2Parallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
            return true;
        }
        catch (Exception ex) when (IsArgon2idUnavailable(ex))
        {
            return false;
        }
    }

    private static string CreateScrypt(string password)
    {
        var salt = CreateSalt();
        var hash = DeriveScryptBytes(password, salt, DefaultScryptCost, DefaultScryptBlockSize, DefaultScryptParallelism, DefaultHashSizeBytes);
        return $"{ScryptAlgorithmName}$N={DefaultScryptCost},r={DefaultScryptBlockSize},p={DefaultScryptParallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static byte[] DeriveArgon2idBytes(string password, byte[] salt, int memorySizeKiB, int iterations, int parallelism, int hashSizeBytes)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = parallelism,
                Iterations = iterations,
                MemorySize = memorySizeKiB
            };

            return argon2.GetBytes(hashSizeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] DeriveScryptBytes(string password, byte[] salt, int cost, int blockSize, int parallelism, int hashSizeBytes)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            return SCrypt.Generate(passwordBytes, salt, cost, blockSize, parallelism, hashSizeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] DeriveLegacyPbkdf2Bytes(string password, byte[] salt, int iterations, int hashSizeBytes)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, hashSizeBytes);
    }

    private static byte[] CreateSalt()
    {
        byte[] salt = new byte[DefaultSaltSizeBytes];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    private static bool TryParse(string passwordHash, out ParsedAdminPasswordHash parsedHash)
    {
        parsedHash = default;

        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            return false;
        }

        var parts = passwordHash.Split('$', StringSplitOptions.RemoveEmptyEntries);

        return parts.Length switch
        {
            5 when string.Equals(parts[0], Argon2idAlgorithmName, StringComparison.OrdinalIgnoreCase) => TryParseArgon2id(parts, out parsedHash),
            4 when string.Equals(parts[0], ScryptAlgorithmName, StringComparison.OrdinalIgnoreCase) => TryParseScrypt(parts, out parsedHash),
            5 when string.Equals(parts[0], LegacyPbkdf2AlgorithmName, StringComparison.OrdinalIgnoreCase) => TryParseLegacyPbkdf2(parts, out parsedHash),
            _ => false
        };
    }

    private static bool TryParseArgon2id(string[] parts, out ParsedAdminPasswordHash parsedHash)
    {
        parsedHash = default;

        if (!string.Equals(parts[1], $"v={CurrentArgon2Version}", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!TryParseNamedParameters(parts[2], out var parameters)
            || !TryGetPositiveInt(parameters, "m", out var memorySizeKiB)
            || !TryGetPositiveInt(parameters, "t", out var iterations)
            || !TryGetPositiveInt(parameters, "p", out var parallelism))
        {
            return false;
        }

        if (!TryDecodeBytes(parts[3], out var salt) || !TryDecodeBytes(parts[4], out var expectedHash))
        {
            return false;
        }

        parsedHash = new ParsedAdminPasswordHash(AdminPasswordHashAlgorithm.Argon2id, memorySizeKiB, iterations, parallelism, salt, expectedHash);
        return true;
    }

    private static bool TryParseScrypt(string[] parts, out ParsedAdminPasswordHash parsedHash)
    {
        parsedHash = default;

        if (!TryParseNamedParameters(parts[1], out var parameters)
            || !TryGetPositiveInt(parameters, "N", out var cost)
            || !TryGetPositiveInt(parameters, "r", out var blockSize)
            || !TryGetPositiveInt(parameters, "p", out var parallelism))
        {
            return false;
        }

        if (!TryDecodeBytes(parts[2], out var salt) || !TryDecodeBytes(parts[3], out var expectedHash))
        {
            return false;
        }

        parsedHash = new ParsedAdminPasswordHash(AdminPasswordHashAlgorithm.Scrypt, cost, blockSize, parallelism, salt, expectedHash);
        return true;
    }

    private static bool TryParseLegacyPbkdf2(string[] parts, out ParsedAdminPasswordHash parsedHash)
    {
        parsedHash = default;

        if (!string.Equals(parts[1], LegacyPbkdf2HashAlgorithmName, StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(parts[2], out var iterations)
            || iterations <= 0)
        {
            return false;
        }

        if (!TryDecodeBytes(parts[3], out var salt) || !TryDecodeBytes(parts[4], out var expectedHash))
        {
            return false;
        }

        parsedHash = new ParsedAdminPasswordHash(AdminPasswordHashAlgorithm.LegacyPbkdf2, iterations, 0, 0, salt, expectedHash);
        return true;
    }

    private static bool TryParseNamedParameters(string raw, out Dictionary<string, string> parameters)
    {
        parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var segment in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var delimiterIndex = segment.IndexOf('=');
            if (delimiterIndex <= 0 || delimiterIndex == segment.Length - 1)
            {
                return false;
            }

            parameters[segment[..delimiterIndex]] = segment[(delimiterIndex + 1)..];
        }

        return parameters.Count > 0;
    }

    private static bool TryGetPositiveInt(IReadOnlyDictionary<string, string> parameters, string name, out int value)
    {
        value = 0;
        return parameters.TryGetValue(name, out var raw)
            && int.TryParse(raw, out value)
            && value > 0;
    }

    private static bool TryDecodeBytes(string raw, out byte[] value)
    {
        value = Array.Empty<byte>();

        try
        {
            value = Convert.FromBase64String(raw);
            return value.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsArgon2idAvailable()
    {
        return TryCreateArgon2id("availability-probe", out _);
    }

    private static bool IsArgon2idUnavailable(Exception exception)
    {
        return exception is PlatformNotSupportedException
            or NotSupportedException
            or TypeLoadException
            or FileNotFoundException
            or MissingMethodException;
    }

    private enum AdminPasswordHashAlgorithm
    {
        Argon2id,
        Scrypt,
        LegacyPbkdf2
    }

    private readonly record struct ParsedAdminPasswordHash(
        AdminPasswordHashAlgorithm Algorithm,
        int Cost1,
        int Cost2,
        int Cost3,
        byte[] Salt,
        byte[] ExpectedHash);
}
