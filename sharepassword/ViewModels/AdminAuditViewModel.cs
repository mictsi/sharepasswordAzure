using SharePassword.Models;

namespace SharePassword.ViewModels;

public class AdminAuditViewModel
{
    public string? ErrorMessage { get; set; }
    public IReadOnlyCollection<AuditLog> Logs { get; set; } = Array.Empty<AuditLog>();
    public string? Search { get; set; }
    public string? Actor { get; set; }
    public string SelectedRange { get; set; } = AdminAuditRangeOption.All;
    public string SelectedOperation { get; set; } = AdminAuditOperationOption.All;
    public string SelectedSuccess { get; set; } = AdminAuditSuccessOption.All;
    public IReadOnlyList<string> AvailableOperations { get; set; } = Array.Empty<string>();
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 100;
    public int TotalCount { get; set; }
    public IReadOnlyList<AuditLog> ExportLogs { get; set; } = Array.Empty<AuditLog>();

    public int TotalPages => TotalCount <= 0 ? 1 : (int)Math.Ceiling(TotalCount / (double)PageSize);
    public bool HasPreviousPage => Page > 1;
    public bool HasNextPage => Page < TotalPages;
    public bool HasFilters => !string.IsNullOrWhiteSpace(Search)
        || !string.IsNullOrWhiteSpace(Actor)
        || !string.Equals(SelectedRange, AdminAuditRangeOption.All, StringComparison.Ordinal)
        || !string.Equals(SelectedOperation, AdminAuditOperationOption.All, StringComparison.Ordinal)
        || !string.Equals(SelectedSuccess, AdminAuditSuccessOption.All, StringComparison.Ordinal);
}
