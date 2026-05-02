using System.ComponentModel.DataAnnotations;

namespace SharePassword.ViewModels;

public class ApplicationSettingsViewModel
{
    public bool IsSupported { get; set; }
    public ApplicationTimeZoneSettingsViewModel TimeZone { get; set; } = new();
    public ShareAccessPauseSettingsViewModel ShareAccessPause { get; set; } = new();
    public string? StatusMessage { get; set; }
}

public class ApplicationTimeZoneSettingsViewModel
{
    public string TimeZoneId { get; set; } = "UTC";
    public IReadOnlyList<TimeZoneOptionViewModel> AvailableTimeZones { get; set; } = Array.Empty<TimeZoneOptionViewModel>();
}

public class ShareAccessPauseSettingsViewModel
{
    [Range(1, 100, ErrorMessage = "Failed attempt limit must be between 1 and 100.")]
    [Display(Name = "Failed attempts before pause")]
    public int ShareAccessFailedAttemptLimit { get; set; } = 5;

    [Range(1, 1440, ErrorMessage = "Pause duration must be between 1 and 1440 minutes.")]
    [Display(Name = "Pause duration")]
    public int ShareAccessPauseMinutes { get; set; } = 15;
}

public class TimeZoneOptionViewModel
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}
