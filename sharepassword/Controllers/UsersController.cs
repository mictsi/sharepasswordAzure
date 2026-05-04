using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharePassword.Models;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

[Authorize(Policy = "AdminOnly")]
public class UsersController : Controller
{
    private readonly ILocalUserService _localUserService;
    private readonly IAuditLogger _auditLogger;
    private readonly IUsageMetricsService _usageMetricsService;

    public UsersController(ILocalUserService localUserService, IAuditLogger auditLogger, IUsageMetricsService usageMetricsService)
    {
        _localUserService = localUserService;
        _auditLogger = auditLogger;
        _usageMetricsService = usageMetricsService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var users = _localUserService.IsSupported ? await _localUserService.GetAllAsync() : Array.Empty<LocalUser>();
        var model = new LocalUserIndexViewModel
        {
            IsSupported = _localUserService.IsSupported,
            StatusMessage = TempData["StatusMessage"]?.ToString(),
            Users = users
                .OrderBy(user => user.Username, StringComparer.OrdinalIgnoreCase)
                .Select(MapListItem)
                .ToList()
        };

        return View(model);
    }

    [HttpGet]
    public IActionResult Create()
    {
        return View(BuildEditorModel(new LocalUserEditorViewModel()));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(LocalUserEditorViewModel model)
    {
        if (string.IsNullOrWhiteSpace(model.NewPassword))
        {
            ModelState.AddModelError(nameof(model.NewPassword), "A password is required.");
        }
        else
        {
            AddPasswordPolicyErrors(nameof(model.NewPassword), model.NewPassword);
        }

        if (!string.Equals(model.NewPassword, model.ConfirmPassword, StringComparison.Ordinal))
        {
            ModelState.AddModelError(nameof(model.ConfirmPassword), "The password confirmation does not match.");
        }

        if (!ModelState.IsValid)
        {
            return View(BuildEditorModel(model));
        }

        var actor = GetCurrentUserIdentifier();
        var result = await _localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = model.Username,
            DisplayName = model.DisplayName,
            Email = model.Email,
            Roles = model.SelectedRoles,
            Password = model.NewPassword,
            IsDisabled = model.IsDisabled,
            IsTotpRequired = model.IsTotpRequired
        }, actor);

        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Unable to create the user.");
            await _auditLogger.LogAsync("admin", actor, "local-user.create", false, details: result.ErrorMessage);
            return View(BuildEditorModel(model));
        }

        await _auditLogger.LogAsync("admin", actor, "local-user.create", true, targetType: "LocalUser", targetId: result.User!.Id.ToString());
        await _usageMetricsService.RecordAsync("local-user.create", "admin", actor, relatedId: result.User!.Id.ToString(), details: $"Local user {result.User.Username} created.");
        TempData["StatusMessage"] = "User created.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Edit(Guid id)
    {
        var user = await _localUserService.GetByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        return View(BuildEditorModel(MapEditorModel(user)));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(Guid id, LocalUserEditorViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(BuildEditorModel(model));
        }

        var actor = GetCurrentUserIdentifier();
        var result = await _localUserService.UpdateAsync(id, new LocalUserUpsertRequest
        {
            Username = model.Username,
            DisplayName = model.DisplayName,
            Email = model.Email,
            Roles = model.SelectedRoles,
            IsDisabled = model.IsDisabled,
            IsTotpRequired = model.IsTotpRequired
        }, actor);

        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Unable to update the user.");
            await _auditLogger.LogAsync("admin", actor, "local-user.update", false, targetType: "LocalUser", targetId: id.ToString(), details: result.ErrorMessage);
            return View(BuildEditorModel(model));
        }

        await _auditLogger.LogAsync("admin", actor, "local-user.update", true, targetType: "LocalUser", targetId: id.ToString());
        await _usageMetricsService.RecordAsync("local-user.update", "admin", actor, relatedId: id.ToString(), details: $"Local user {result.User!.Username} updated.");
        TempData["StatusMessage"] = "User updated.";
        return RedirectToAction(nameof(Edit), new { id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(LocalUserPasswordResetViewModel model)
    {
        if (string.IsNullOrWhiteSpace(model.NewPassword))
        {
            ModelState.AddModelError(nameof(model.NewPassword), "A new password is required.");
        }
        else
        {
            AddPasswordPolicyErrors(nameof(model.NewPassword), model.NewPassword);
        }

        if (!string.Equals(model.NewPassword, model.ConfirmPassword, StringComparison.Ordinal))
        {
            ModelState.AddModelError(nameof(model.ConfirmPassword), "The password confirmation does not match.");
        }

        if (!ModelState.IsValid)
        {
            var user = await _localUserService.GetByIdAsync(model.UserId);
            if (user is null)
            {
                return NotFound();
            }

            var editor = BuildEditorModel(MapEditorModel(user));
            editor.ResetPassword = model;
            return View("Edit", editor);
        }

        var actor = GetCurrentUserIdentifier();
        var result = await _localUserService.ResetPasswordAsync(model.UserId, model.NewPassword, actor);
        if (!result.Succeeded)
        {
            TempData["StatusMessage"] = result.ErrorMessage ?? "Password reset failed.";
            await _auditLogger.LogAsync("admin", actor, "local-user.reset-password", false, targetType: "LocalUser", targetId: model.UserId.ToString(), details: result.ErrorMessage);
            return RedirectToAction(nameof(Edit), new { id = model.UserId });
        }

        await _auditLogger.LogAsync("admin", actor, "local-user.reset-password", true, targetType: "LocalUser", targetId: model.UserId.ToString());
        await _usageMetricsService.RecordAsync("local-user.reset-password", "admin", actor, relatedId: model.UserId.ToString(), details: $"Password reset for {result.User!.Username}.");
        TempData["StatusMessage"] = "Password reset.";
        return RedirectToAction(nameof(Edit), new { id = model.UserId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveTotp(Guid id)
    {
        var actor = GetCurrentUserIdentifier();
        var result = await _localUserService.RemoveTotpAsync(id, actor);
        if (!result.Succeeded)
        {
            TempData["StatusMessage"] = result.ErrorMessage ?? "Unable to reset authenticator app setup.";
            await _auditLogger.LogAsync("admin", actor, "local-user.totp.reset", false, targetType: "LocalUser", targetId: id.ToString(), details: result.ErrorMessage);
            return RedirectToAction(nameof(Edit), new { id });
        }

        await _auditLogger.LogAsync("admin", actor, "local-user.totp.reset", true, targetType: "LocalUser", targetId: id.ToString());
        await _usageMetricsService.RecordAsync("local-user.totp.reset", "admin", actor, relatedId: id.ToString(), details: $"TOTP setup reset for {result.User!.Username}.");
        TempData["StatusMessage"] = "Authenticator app setup reset.";
        return RedirectToAction(nameof(Edit), new { id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id)
    {
        var actor = GetCurrentUserIdentifier();
        var result = await _localUserService.DeleteAsync(id, actor);
        if (!result.Succeeded)
        {
            TempData["StatusMessage"] = result.ErrorMessage ?? "Unable to delete the user.";
            await _auditLogger.LogAsync("admin", actor, "local-user.delete", false, targetType: "LocalUser", targetId: id.ToString(), details: result.ErrorMessage);
            return RedirectToAction(nameof(Edit), new { id });
        }

        await _auditLogger.LogAsync("admin", actor, "local-user.delete", true, targetType: "LocalUser", targetId: id.ToString());
        await _usageMetricsService.RecordAsync("local-user.delete", "admin", actor, relatedId: id.ToString(), details: $"Local user {result.User!.Username} deleted.");
        TempData["StatusMessage"] = "User deleted.";
        return RedirectToAction(nameof(Index));
    }

    private LocalUserEditorViewModel BuildEditorModel(LocalUserEditorViewModel model)
    {
        model.AvailableRoles = _localUserService.GetAvailableRoles();
        model.SelectedRoles ??= Array.Empty<string>();
        model.ResetPassword ??= new LocalUserPasswordResetViewModel { UserId = model.Id, Username = model.Username };
        model.StatusMessage ??= TempData["StatusMessage"]?.ToString();
        return model;
    }

    private static LocalUserListItemViewModel MapListItem(LocalUser user)
    {
        return new LocalUserListItemViewModel
        {
            Id = user.Id,
            Username = user.Username,
            DisplayName = user.DisplayName,
            Email = user.Email,
            Roles = user.Roles.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            IsDisabled = user.IsDisabled,
            IsSeededAdmin = user.IsSeededAdmin,
            IsTotpRequired = user.IsTotpRequired,
            IsTotpConfigured = HasConfirmedTotp(user),
            LastLoginAtUtc = user.LastLoginAtUtc,
            LastShareCreatedAtUtc = user.LastShareCreatedAtUtc,
            LastPasswordResetAtUtc = user.LastPasswordResetAtUtc,
            TotalSuccessfulLogins = user.TotalSuccessfulLogins,
            TotalSharesCreated = user.TotalSharesCreated
        };
    }

    private static LocalUserEditorViewModel MapEditorModel(LocalUser user)
    {
        return new LocalUserEditorViewModel
        {
            Id = user.Id,
            Username = user.Username,
            DisplayName = user.DisplayName,
            Email = user.Email,
            SelectedRoles = user.Roles.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            IsDisabled = user.IsDisabled,
            IsSeededAdmin = user.IsSeededAdmin,
            IsTotpRequired = user.IsTotpRequired,
            IsTotpConfigured = HasConfirmedTotp(user),
            LastLoginAtUtc = user.LastLoginAtUtc,
            LastShareCreatedAtUtc = user.LastShareCreatedAtUtc,
            LastPasswordResetAtUtc = user.LastPasswordResetAtUtc,
            TotalSuccessfulLogins = user.TotalSuccessfulLogins,
            TotalSharesCreated = user.TotalSharesCreated,
            ResetPassword = new LocalUserPasswordResetViewModel
            {
                UserId = user.Id,
                Username = user.Username
            }
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

    private void AddPasswordPolicyErrors(string key, string password)
    {
        foreach (var error in LocalUserPasswordPolicy.Validate(password))
        {
            ModelState.AddModelError(key, error);
        }
    }

    private static bool HasConfirmedTotp(LocalUser user)
    {
        return !string.IsNullOrWhiteSpace(user.TotpSecretEncrypted) && user.TotpConfirmedAtUtc is not null;
    }
}
