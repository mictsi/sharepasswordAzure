namespace SharePassword.Services;

internal static class LocalUserPasswordPolicy
{
    public const int MinimumLength = 12;

    public static IReadOnlyList<string> Validate(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return ["A password is required."];
        }

        var errors = new List<string>();
        if (password.Length < MinimumLength)
        {
            errors.Add($"Password must be at least {MinimumLength} characters long.");
        }

        if (!password.Any(char.IsLower))
        {
            errors.Add("Password must include a lowercase letter.");
        }

        if (!password.Any(char.IsUpper))
        {
            errors.Add("Password must include an uppercase letter.");
        }

        if (!password.Any(char.IsDigit))
        {
            errors.Add("Password must include a number.");
        }

        if (!password.Any(character => !char.IsLetterOrDigit(character)))
        {
            errors.Add("Password must include a symbol.");
        }

        return errors;
    }
}
