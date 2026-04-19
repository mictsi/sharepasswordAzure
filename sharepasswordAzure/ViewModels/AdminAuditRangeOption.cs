namespace SharePassword.ViewModels;

public static class AdminAuditRangeOption
{
    public const string LastDay = "last-day";
    public const string ThisWeek = "this-week";
    public const string ThisMonth = "this-month";
    public const string Last3Months = "last-3-months";
    public const string Last6Months = "last-6-months";
    public const string All = "all";

    public static readonly IReadOnlyList<string> AllValues =
    [
        LastDay,
        ThisWeek,
        ThisMonth,
        Last3Months,
        Last6Months,
        All
    ];

    public static string Normalize(string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? All : value.Trim().ToLowerInvariant();
        return AllValues.Contains(normalized, StringComparer.Ordinal) ? normalized : All;
    }

    public static string GetLabel(string value)
    {
        return Normalize(value) switch
        {
            LastDay => "Last day",
            ThisWeek => "This week",
            ThisMonth => "This month",
            Last3Months => "Last 3 months",
            Last6Months => "Last 6 months",
            _ => "All logs"
        };
    }
}