using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

public class AccountController : Controller
{
    private readonly AdminAuthOptions _adminAuthOptions;
    private readonly OidcAuthOptions _oidcAuthOptions;
    private readonly IAuditLogger _auditLogger;
    private readonly ILocalUserService _localUserService;
    private readonly IUsageMetricsService _usageMetricsService;
    private readonly string _adminRoleName;
    private readonly string _userRoleName;

    public AccountController(
        IOptions<AdminAuthOptions> adminAuthOptions,
        IOptions<OidcAuthOptions> oidcAuthOptions,
        IAuditLogger auditLogger,
        ILocalUserService localUserService,
        IUsageMetricsService usageMetricsService)
    {
        _adminAuthOptions = adminAuthOptions.Value;
        _oidcAuthOptions = oidcAuthOptions.Value;
        _auditLogger = auditLogger;
        _localUserService = localUserService;
        _usageMetricsService = usageMetricsService;
        _adminRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.AdminRoleName) ? "Admin" : _oidcAuthOptions.AdminRoleName.Trim();
        _userRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.UserRoleName) ? "User" : _oidcAuthOptions.UserRoleName.Trim();
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (!IsLocalRequest())
        {
            if (_oidcAuthOptions.Enabled)
            {
                return RedirectToAction(nameof(ExternalLogin), new { returnUrl });
            }

            return Forbid();
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["OidcEnabled"] = _oidcAuthOptions.Enabled;
        return View(new AdminLoginViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(AdminLoginViewModel model, string? returnUrl = null)
    {
        if (!IsLocalRequest())
        {
            if (_oidcAuthOptions.Enabled)
            {
                return RedirectToAction(nameof(ExternalLogin), new { returnUrl });
            }

            return Forbid();
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["OidcEnabled"] = _oidcAuthOptions.Enabled;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        LocalUser? existingLocalUser = null;
        if (_localUserService.IsSupported)
        {
            try
            {
                existingLocalUser = await _localUserService.GetByUsernameAsync(model.Username);
            }
            catch (DatabaseOperationException exception)
            {
                ModelState.AddModelError(string.Empty, exception.UserMessage);
                return View(model);
            }
        }

        if (existingLocalUser is not null)
        {
            var localAuthentication = await _localUserService.AuthenticateAsync(model.Username, model.Password);
            if (!localAuthentication.Succeeded || localAuthentication.User is null)
            {
                await _auditLogger.LogAsync("admin", model.Username, "local-user.login", false, details: localAuthentication.ErrorMessage ?? "Invalid username/password.");
                ModelState.AddModelError(string.Empty, localAuthentication.ErrorMessage ?? "Invalid login attempt.");
                return View(model);
            }

            await SignInLocalUserAsync(localAuthentication.User);
            await _localUserService.RecordSuccessfulLoginAsync(localAuthentication.User.Id);

            var isAdmin = localAuthentication.User.Roles.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Contains(_adminRoleName, StringComparer.OrdinalIgnoreCase);
            var actorType = isAdmin ? "admin" : "user";
            var operation = isAdmin ? "admin.login" : "user.login";
            var metricKey = isAdmin ? DbUsageMetricsService.AdminLoginKey : DbUsageMetricsService.UserLoginKey;

            await _auditLogger.LogAsync(actorType, localAuthentication.User.Username, operation, true);
            await _usageMetricsService.RecordAsync(metricKey, actorType, localAuthentication.User.Username, details: "Local user sign-in succeeded.");

            return RedirectToAction(nameof(PostLogin), new { returnUrl });
        }

        var validUsername = string.Equals(model.Username, _adminAuthOptions.Username, StringComparison.OrdinalIgnoreCase);
        var validPassword = AdminPasswordHash.Verify(model.Password, _adminAuthOptions.PasswordHash);

        if (!validUsername || !validPassword)
        {
            await _auditLogger.LogAsync("admin", model.Username, "admin.login", false, details: "Invalid username/password.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, _adminAuthOptions.Username),
            new(ClaimTypes.Role, _adminRoleName),
            new(ClaimTypes.Role, _userRoleName),
            new("auth_source", "config-admin")
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = false
            });

        await _auditLogger.LogAsync("admin", _adminAuthOptions.Username, "admin.login", true);
        await _usageMetricsService.RecordAsync(DbUsageMetricsService.AdminLoginKey, "admin", _adminAuthOptions.Username, details: "Configured admin sign-in succeeded.");

        return RedirectToAction(nameof(PostLogin), new { returnUrl });
    }

    [Authorize]
    [HttpGet]
    public IActionResult PostLogin(string? returnUrl = null)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl!);
        }

        if (User.IsInRole(_adminRoleName) || User.IsInRole(_userRoleName))
        {
            return RedirectToAction("Index", "Admin");
        }

        if (CanAccessAuditLogs())
        {
            return RedirectToAction("Audit", "Admin");
        }

        return RedirectToAction(nameof(Login));
    }

    [HttpGet]
    public async Task<IActionResult> ExternalLogin(string? returnUrl = null)
    {
        if (!_oidcAuthOptions.Enabled)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var redirectUri = ApplicationPathHelper.BuildAppPath(Request.PathBase, Url.Action(nameof(PostLogin), new { returnUrl }) ?? "/");

        await _auditLogger.LogAsync(
            "admin",
            User.FindFirstValue("preferred_username")
                ?? User.FindFirstValue("email")
                ?? User.FindFirstValue("upn")
                ?? User.FindFirstValue("unique_name")
                ?? User.FindFirstValue(ClaimTypes.Name)
                ?? User.Identity?.Name
                ?? User.FindFirstValue("oid")
                ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? "unknown",
            "oidc.login.attempt",
            true,
            details: $"OIDC challenge initiated. returnUrl={returnUrl ?? string.Empty}");

        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var username = User.Identity?.Name ?? "unknown";

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await _auditLogger.LogAsync("admin", username, "admin.logout", true);

        if (_oidcAuthOptions.Enabled)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = ApplicationPathHelper.BuildAppPath(Request.PathBase, Url.Action(nameof(Login)) ?? "/")
            };

            return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, CookieAuthenticationDefaults.AuthenticationScheme);
        }

        return RedirectToAction(nameof(Login));
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Profile()
    {
        var model = await BuildProfileViewModelAsync();
        return View(model);
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Profile(ProfileViewModel model)
    {
        var profile = await BuildProfileViewModelAsync();
        profile.CurrentPassword = model.CurrentPassword;
        profile.NewPassword = model.NewPassword;
        profile.ConfirmPassword = model.ConfirmPassword;

        if (!profile.IsLocalAccount)
        {
            ModelState.AddModelError(string.Empty, "This account is managed outside the local user store.");
            return View(profile);
        }

        if (string.IsNullOrWhiteSpace(profile.NewPassword))
        {
            ModelState.AddModelError(nameof(profile.NewPassword), "A new password is required.");
        }

        if (!string.Equals(profile.NewPassword, profile.ConfirmPassword, StringComparison.Ordinal))
        {
            ModelState.AddModelError(nameof(profile.ConfirmPassword), "The new password confirmation does not match.");
        }

        if (!ModelState.IsValid)
        {
            return View(profile);
        }

        var localUserId = GetCurrentLocalUserId();
        if (localUserId is null)
        {
            ModelState.AddModelError(string.Empty, "Unable to resolve the current local user account.");
            return View(profile);
        }

        var result = await _localUserService.ChangeOwnPasswordAsync(localUserId.Value, profile.CurrentPassword, profile.NewPassword);
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Password change failed.");
            return View(profile);
        }

        var actor = GetCurrentUserIdentifier();
        await _auditLogger.LogAsync(GetCurrentActorType(), actor, "local-user.change-password", true, targetType: "LocalUser", targetId: localUserId.Value.ToString());
        await _usageMetricsService.RecordAsync("local-user.change-password", GetCurrentActorType(), actor, relatedId: localUserId.Value.ToString(), details: "User changed their own password.");

        TempData["StatusMessage"] = "Password updated.";
        return RedirectToAction(nameof(Profile));
    }

    private bool IsLocalRequest()
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress;

        if (remoteIp is null)
        {
            return true;
        }

        if (IPAddress.IsLoopback(remoteIp))
        {
            return true;
        }

        var localIp = HttpContext.Connection.LocalIpAddress;
        return localIp is not null && remoteIp.Equals(localIp);
    }

    private async Task SignInLocalUserAsync(LocalUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new("local_user_id", user.Id.ToString()),
            new("auth_source", "local")
        };

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, user.Email));
        }

        foreach (var role in user.Roles.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = false
            });
    }

    private async Task<ProfileViewModel> BuildProfileViewModelAsync()
    {
        var localUserId = GetCurrentLocalUserId();
        LocalUser? localUser = null;

        if (localUserId.HasValue)
        {
            localUser = await _localUserService.GetByIdAsync(localUserId.Value);
        }

        var roles = User.Claims
            .Where(claim => claim.Type == ClaimTypes.Role)
            .Select(claim => claim.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(role => role, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ProfileViewModel
        {
            Username = localUser?.Username ?? GetCurrentUserIdentifier(),
            DisplayName = localUser?.DisplayName ?? GetCurrentUserIdentifier(),
            Email = localUser?.Email ?? User.FindFirstValue(ClaimTypes.Email) ?? string.Empty,
            Roles = roles,
            IsLocalAccount = localUser is not null,
            LastLoginAtUtc = localUser?.LastLoginAtUtc,
            LastShareCreatedAtUtc = localUser?.LastShareCreatedAtUtc,
            LastPasswordResetAtUtc = localUser?.LastPasswordResetAtUtc,
            TotalSuccessfulLogins = localUser?.TotalSuccessfulLogins ?? 0,
            TotalSharesCreated = localUser?.TotalSharesCreated ?? 0,
            StatusMessage = TempData["StatusMessage"]?.ToString()
        };
    }

    private Guid? GetCurrentLocalUserId()
    {
        var raw = User.FindFirstValue("local_user_id") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(raw, out var localUserId) ? localUserId : null;
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

    private string GetCurrentActorType()
    {
        return User.IsInRole(_adminRoleName) ? "admin" : "user";
    }

    private bool CanAccessAuditLogs()
    {
        return User.IsInRole(_adminRoleName) || User.IsInRole(BuiltInRoleNames.Auditor);
    }

}
