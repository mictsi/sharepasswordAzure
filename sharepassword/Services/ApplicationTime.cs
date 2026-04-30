using System.Globalization;
using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class ApplicationTime : IApplicationTime
{
    private readonly ITimeZoneSettingsProvider _timeZoneSettingsProvider;

    public ApplicationTime(ITimeZoneSettingsProvider timeZoneSettingsProvider)
    {
        _timeZoneSettingsProvider = timeZoneSettingsProvider;
    }

    public DateTime UtcNow => DateTime.UtcNow;

    public DateTimeOffset Now => ConvertUtcToApplicationTime(UtcNow);

    public TimeZoneInfo TimeZone => _timeZoneSettingsProvider.GetCurrentTimeZone();

    public string TimeZoneId => _timeZoneSettingsProvider.GetCurrentTimeZoneId();

    public DateTimeOffset ConvertUtcToApplicationTime(DateTime utcDateTime)
    {
        var normalizedUtc = utcDateTime.Kind switch
        {
            DateTimeKind.Utc => utcDateTime,
            DateTimeKind.Local => utcDateTime.ToUniversalTime(),
            _ => DateTime.SpecifyKind(utcDateTime, DateTimeKind.Utc)
        };

        return TimeZoneInfo.ConvertTime(new DateTimeOffset(normalizedUtc, TimeSpan.Zero), TimeZone);
    }

    public string FormatUtcForDisplay(DateTime utcDateTime)
    {
        return ConvertUtcToApplicationTime(utcDateTime)
            .ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
    }
}