namespace SharePassword.ViewModels;

public class LocalUserIndexViewModel
{
    public bool IsSupported { get; set; }
    public string? StatusMessage { get; set; }
    public IReadOnlyList<LocalUserListItemViewModel> Users { get; set; } = Array.Empty<LocalUserListItemViewModel>();
}