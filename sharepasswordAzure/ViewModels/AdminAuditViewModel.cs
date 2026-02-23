using SharePassword.Models;

namespace SharePassword.ViewModels;

public class AdminAuditViewModel
{
    public IReadOnlyCollection<AuditLog> Logs { get; set; } = Array.Empty<AuditLog>();
    public string? Search { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 100;
    public int TotalCount { get; set; }

    public int TotalPages => TotalCount <= 0 ? 1 : (int)Math.Ceiling(TotalCount / (double)PageSize);
    public bool HasPreviousPage => Page > 1;
    public bool HasNextPage => Page < TotalPages;
}
