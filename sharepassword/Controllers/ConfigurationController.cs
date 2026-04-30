using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

        await _auditLogger.LogAsync("admin", actor, "mail-configuration.update", true);
        await _usageMetricsService.RecordAsync("mail-configuration.update", "admin", actor, details: "Mail configuration updated.");
        TempData["StatusMessage"] = "Mail configuration saved.";
        return RedirectToAction(nameof(Mail));
    }

    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        var configuration = await _systemConfigurationService.GetConfigurationAsync();
        return View(BuildSettingsModel(configuration.TimeZoneId));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Settings(ApplicationSettingsViewModel model)
    {
        if (!_systemConfigurationService.IsSupported)
        {
            ModelState.AddModelError(string.Empty, "Editable application settings are only available for database-backed storage backends.");
            return View(BuildSettingsModel(model.TimeZoneId, supported: false));
        }

        if (!ModelState.IsValid)
        {
            return View(BuildSettingsModel(model.TimeZoneId));
        }

        var actor = GetCurrentUserIdentifier();
        try
        {
            await _systemConfigurationService.UpdateTimeZoneAsync(model.TimeZoneId, actor);
        }
        catch (TimeZoneNotFoundException ex)
        {
            ModelState.AddModelError(nameof(model.TimeZoneId), ex.Message);
            return View(BuildSettingsModel(model.TimeZoneId));
        }

        await _auditLogger.LogAsync("admin", actor, "settings.update", true, details: $"Time zone set to {model.TimeZoneId}.");
        await _usageMetricsService.RecordAsync("settings.update", "admin", actor, details: $"Time zone set to {model.TimeZoneId}.");
        TempData["StatusMessage"] = "Settings saved.";
        return RedirectToAction(nameof(Settings));
    }

    private ApplicationSettingsViewModel BuildSettingsModel(string? selectedTimeZoneId, bool supported = true)
    {
        var selected = string.IsNullOrWhiteSpace(selectedTimeZoneId) ? "UTC" : selectedTimeZoneId.Trim();
        return new ApplicationSettingsViewModel
        {
            IsSupported = supported,
            TimeZoneId = selected,
            StatusMessage = TempData["StatusMessage"]?.ToString(),
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