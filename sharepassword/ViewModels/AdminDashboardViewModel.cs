namespace SharePassword.ViewModels;

public class AdminDashboardViewModel
{
    public string Search { get; set; } = string.Empty;
    public string SelectedStatus { get; set; } = AdminShareStatusOption.All;
    public int ActiveCount { get; set; }
    public int ExpiringSoonCount { get; set; }
    public int AccessedCount { get; set; }
    public int RevokedCount { get; set; }
    public int TotalVisibleShares { get; set; }
    public long TotalSharesCreatedKpi { get; set; }
    public long TotalShareAccessesKpi { get; set; }
    public long AdminLoginsKpi { get; set; }
    public long ExpiredSharesDeletedKpi { get; set; }
    public long ExpiredUnusedSharesDeletedKpi { get; set; }
    public IReadOnlyList<AdminShareListItemViewModel> Shares { get; set; } = Array.Empty<AdminShareListItemViewModel>();

    public bool HasShares => TotalVisibleShares > 0;
    public bool HasResults => Shares.Count > 0;
    public bool HasFilters => !string.IsNullOrWhiteSpace(Search)
        || !string.Equals(SelectedStatus, AdminShareStatusOption.All, StringComparison.Ordinal);
}

public static class AdminShareStatusOption
{
    public const string All = "all";
    public const string Active = "active";
    public const string ExpiringSoon = "expiring-soon";
    public const string Accessed = "accessed";
    public const string Expired = "expired";

    public static readonly IReadOnlyList<string> AllValues =
    [
        All,
        Active,
        ExpiringSoon,
        Accessed,
        Expired
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
            Active => "Active",
            ExpiringSoon => "Expiring soon",
            Accessed => "Accessed",
            Expired => "Expired",
            _ => "All statuses"
        };
    }
}