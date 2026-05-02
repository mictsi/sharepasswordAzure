using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharePassword.Models;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

[Authorize(Policy = "AdminOnly")]
public class ConfigurationController : Controller
{
    private readonly ISystemConfigurationService _systemConfigurationService;
    private readonly IAuditLogger _auditLogger;
    private readonly IUsageMetricsService _usageMetricsService;

    public ConfigurationController(ISystemConfigurationService systemConfigurationService, IAuditLogger auditLogger, IUsageMetricsService usageMetricsService)
    {
        _systemConfigurationService = systemConfigurationService;
        _auditLogger = auditLogger;
        _usageMetricsService = usageMetricsService;
    }

    [HttpGet]
    public async Task<IActionResult> Mail()
    {
        var configuration = await _systemConfigurationService.GetConfigurationAsync();
        return View(new MailConfigurationViewModel
        {
            IsSupported = _systemConfigurationService.IsSupported,
            SmtpHost = configuration.SmtpHost,
            SmtpPort = configuration.SmtpPort,
            SmtpUsername = configuration.SmtpUsername,
            SmtpPassword = configuration.SmtpPassword,
            UseTls = configuration.UseTls,
            SenderEmail = configuration.SenderEmail,
            SenderDisplayName = configuration.SenderDisplayName,
            AdminNotificationRecipients = configuration.AdminNotificationRecipients,
            NotifyAdminsOnShareAccess = configuration.NotifyAdminsOnShareAccess,
            NotifyCreatorOnShareAccess = configuration.NotifyCreatorOnShareAccess,
            ShareAccessedSubjectTemplate = configuration.ShareAccessedSubjectTemplate,
            ShareAccessedBodyTemplate = configuration.ShareAccessedBodyTemplate,
            StatusMessage = TempData["StatusMessage"]?.ToString()
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Mail(MailConfigurationViewModel model)
    {
        model.IsSupported = _systemConfigurationService.IsSupported;

        if (!_systemConfigurationService.IsSupported)
        {
            ModelState.AddModelError(string.Empty, "Editable mail configuration is only available for database-backed storage backends.");
            return View(model);
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var actor = GetCurrentUserIdentifier();
        try
        {
            await _systemConfigurationService.UpdateMailConfigurationAsync(new MailConfigurationUpdateRequest
            {
                SmtpHost = model.SmtpHost,
                SmtpPort = model.SmtpPort,
                SmtpUsername = model.SmtpUsername,
                SmtpPassword = model.SmtpPassword,
                UseTls = model.UseTls,
                SenderEmail = model.SenderEmail,
                SenderDisplayName = model.SenderDisplayName,
                AdminNotificationRecipients = model.AdminNotificationRecipients,
                NotifyAdminsOnShareAccess = model.NotifyAdminsOnShareAccess,
                NotifyCreatorOnShareAccess = model.NotifyCreatorOnShareAccess,
                ShareAccessedSubjectTemplate = model.ShareAccessedSubjectTemplate,
                ShareAccessedBodyTemplate = model.ShareAccessedBodyTemplate
            }, actor);
        }
        catch (DatabaseOperationException exception)
        {
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View(model);
        }

        await _auditLogger.LogAsync("admin", actor, "mail-configuration.update", true);
        await _usageMetricsService.RecordAsync("mail-configuration.update", "admin", actor, details: "Mail configuration updated.");
        TempData["StatusMessage"] = "Mail configuration saved.";
        return RedirectToAction(nameof(Mail));
    }

    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        var configuration = await _systemConfigurationService.GetConfigurationAsync();
        return View(BuildSettingsModel(configuration));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveTimeZone([Bind(Prefix = "TimeZone")] ApplicationTimeZoneSettingsViewModel model)
    {
        if (!_systemConfigurationService.IsSupported)
        {
            ModelState.AddModelError(string.Empty, "Editable application settings are only available for database-backed storage backends.");
            return View("Settings", await BuildSettingsModelAsync(timeZone: model, supported: false));
        }

        if (!ModelState.IsValid)
        {
            return View("Settings", await BuildSettingsModelAsync(timeZone: model));
        }

        var actor = GetCurrentUserIdentifier();
        try
        {
            await _systemConfigurationService.UpdateTimeZoneAsync(model.TimeZoneId, actor);
        }
        catch (TimeZoneNotFoundException ex)
        {
            ModelState.AddModelError("TimeZone.TimeZoneId", ex.Message);
            return View("Settings", await BuildSettingsModelAsync(timeZone: model));
        }
        catch (DatabaseOperationException exception)
        {
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View("Settings", await BuildSettingsModelAsync(timeZone: model));
        }

        await _auditLogger.LogAsync("admin", actor, "settings.time-zone.update", true, details: $"Time zone set to {model.TimeZoneId}.");
        await _usageMetricsService.RecordAsync("settings.time-zone.update", "admin", actor, details: "Application time zone updated.");
        TempData["StatusMessage"] = "Time zone saved.";
        return RedirectToAction(nameof(Settings));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveShareAccessPause([Bind(Prefix = "ShareAccessPause")] ShareAccessPauseSettingsViewModel model)
    {
        if (!_systemConfigurationService.IsSupported)
        {
            ModelState.AddModelError(string.Empty, "Editable application settings are only available for database-backed storage backends.");
            return View("Settings", await BuildSettingsModelAsync(shareAccessPause: model, supported: false));
        }

        if (!ModelState.IsValid)
        {
            return View("Settings", await BuildSettingsModelAsync(shareAccessPause: model));
        }

        var actor = GetCurrentUserIdentifier();
        try
        {
            var configuration = await _systemConfigurationService.GetConfigurationAsync();
            await _systemConfigurationService.UpdateApplicationSettingsAsync(new ApplicationSettingsUpdateRequest
            {
                TimeZoneId = configuration.TimeZoneId,
                ShareAccessFailedAttemptLimit = model.ShareAccessFailedAttemptLimit,
                ShareAccessPauseMinutes = model.ShareAccessPauseMinutes
            }, actor);
        }
        catch (DatabaseOperationException exception)
        {
            ModelState.AddModelError(string.Empty, exception.UserMessage);
            return View("Settings", await BuildSettingsModelAsync(shareAccessPause: model));
        }

        await _auditLogger.LogAsync("admin", actor, "settings.share-access-pause.update", true, details: $"shareAccessFailedAttemptLimit={model.ShareAccessFailedAttemptLimit}; shareAccessPauseMinutes={model.ShareAccessPauseMinutes}.");
        await _usageMetricsService.RecordAsync("settings.share-access-pause.update", "admin", actor, details: "Share access pause settings updated.");
        TempData["StatusMessage"] = "Share access pause settings saved.";
        return RedirectToAction(nameof(Settings));
    }

    private async Task<ApplicationSettingsViewModel> BuildSettingsModelAsync(
        ApplicationTimeZoneSettingsViewModel? timeZone = null,
        ShareAccessPauseSettingsViewModel? shareAccessPause = null,
        bool? supported = null)
    {
        var configuration = await _systemConfigurationService.GetConfigurationAsync();
        return BuildSettingsModel(configuration, supported ?? _systemConfigurationService.IsSupported, timeZone, shareAccessPause);
    }

    private ApplicationSettingsViewModel BuildSettingsModel(
        SystemConfiguration configuration,
        bool? supported = null,
        ApplicationTimeZoneSettingsViewModel? timeZone = null,
        ShareAccessPauseSettingsViewModel? shareAccessPause = null)
    {
        return new ApplicationSettingsViewModel
        {
            IsSupported = supported ?? _systemConfigurationService.IsSupported,
            TimeZone = BuildTimeZoneModel(timeZone?.TimeZoneId ?? configuration.TimeZoneId),
            ShareAccessPause = shareAccessPause ?? new ShareAccessPauseSettingsViewModel
            {
                ShareAccessFailedAttemptLimit = configuration.ShareAccessFailedAttemptLimit,
                ShareAccessPauseMinutes = configuration.ShareAccessPauseMinutes
            },
            StatusMessage = TempData["StatusMessage"]?.ToString(),
        };
    }

    private static ApplicationTimeZoneSettingsViewModel BuildTimeZoneModel(string? timeZoneId)
    {
        var selected = string.IsNullOrWhiteSpace(timeZoneId) ? "UTC" : timeZoneId.Trim();
        return new ApplicationTimeZoneSettingsViewModel
        {
            TimeZoneId = selected,
            AvailableTimeZones = TimeZoneInfo.GetSystemTimeZones()
                .OrderBy(zone => zone.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(zone => new TimeZoneOptionViewModel
                {
                    Id = zone.Id,
                    DisplayName = $"{zone.DisplayName} ({zone.Id})"
                })
                .ToList()
        };
    }

    private string GetCurrentUserIdentifier()
    {
        return User.FindFirstValue("preferred_username")
               ?? User.FindFirstValue("email")
               ?? User.FindFirstValue("upn")
               ?? User.FindFirstValue("unique_name")
               ?? User.FindFirstValue(ClaimTypes.Name)
               ?? User.Identity?.Name
               ?? User.FindFirstValue(ClaimTypes.Email)
               ?? User.FindFirstValue("oid")
               ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
               ?? "unknown";
    }
}
