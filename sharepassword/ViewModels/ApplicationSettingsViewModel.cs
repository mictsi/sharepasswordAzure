namespace SharePassword.ViewModels;

public class ApplicationSettingsViewModel
{
    public bool IsSupported { get; set; }
    public string TimeZoneId { get; set; } = "UTC";
    public IReadOnlyList<TimeZoneOptionViewModel> AvailableTimeZones { get; set; } = Array.Empty<TimeZoneOptionViewModel>();
    public string? StatusMessage { get; set; }
}

public class TimeZoneOptionViewModel
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}