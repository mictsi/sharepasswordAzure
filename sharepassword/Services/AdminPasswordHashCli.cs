namespace SharePassword.Services;

public static class AdminPasswordHashCli
{
    public static bool TryRun(string[] args)
    {
        if (args.Length == 0 || !string.Equals(args[0], "hash-admin-password", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (args.Any(arg => string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase)))
        {
            Console.Out.WriteLine("Usage: dotnet run --project .\\sharepassword\\sharepassword.csproj -- hash-admin-password [--password <value>] [--password-env-var <name>]");
            return true;
        }

        string? password = null;

        for (var index = 1; index < args.Length; index += 1)
        {
            if (string.Equals(args[index], "--password", StringComparison.OrdinalIgnoreCase) && index + 1 < args.Length)
            {
                password = args[index + 1];
                index += 1;
                continue;
            }

            if (string.Equals(args[index], "--password-env-var", StringComparison.OrdinalIgnoreCase) && index + 1 < args.Length)
            {
                password = Environment.GetEnvironmentVariable(args[index + 1]);
                index += 1;
                continue;
            }
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            Environment.ExitCode = 1;
            Console.Error.WriteLine("Password is required. Pass --password <value> or --password-env-var <name>.");
            return true;
        }

        Console.Out.WriteLine(AdminPasswordHash.Create(password));
        return true;
    }
}