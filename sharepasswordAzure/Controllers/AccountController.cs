using System.Security.Claims;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SharePassword.Options;
using SharePassword.Services;
using SharePassword.ViewModels;

namespace SharePassword.Controllers;

public class AccountController : Controller
{
    private readonly AdminAuthOptions _adminAuthOptions;
    private readonly OidcAuthOptions _oidcAuthOptions;
    private readonly IAuditLogger _auditLogger;
    private readonly string _adminRoleName;

    public AccountController(
        IOptions<AdminAuthOptions> adminAuthOptions,
        IOptions<OidcAuthOptions> oidcAuthOptions,
        IAuditLogger auditLogger)
    {
        _adminAuthOptions = adminAuthOptions.Value;
        _oidcAuthOptions = oidcAuthOptions.Value;
        _auditLogger = auditLogger;
        _adminRoleName = string.IsNullOrWhiteSpace(_oidcAuthOptions.AdminRoleName) ? "Admin" : _oidcAuthOptions.AdminRoleName.Trim();
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

        var validUsername = string.Equals(model.Username, _adminAuthOptions.Username, StringComparison.OrdinalIgnoreCase);
        var validPassword = string.Equals(model.Password, _adminAuthOptions.Password, StringComparison.Ordinal);

        if (!validUsername || !validPassword)
        {
            await _auditLogger.LogAsync("admin", model.Username, "admin.login", false, details: "Invalid username/password.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, _adminAuthOptions.Username),
            new(ClaimTypes.Role, _adminRoleName)
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        await _auditLogger.LogAsync("admin", _adminAuthOptions.Username, "admin.login", true);

        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl!);
        }

        return RedirectToAction("Index", "Admin");
    }

    [HttpGet]
    public async Task<IActionResult> ExternalLogin(string? returnUrl = null)
    {
        if (!_oidcAuthOptions.Enabled)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var redirectUri = Url.Action("Index", "Admin");
        if (Url.IsLocalUrl(returnUrl))
        {
            redirectUri = returnUrl;
        }

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
                RedirectUri = Url.Action(nameof(Login))
            };

            return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, CookieAuthenticationDefaults.AuthenticationScheme);
        }

        return RedirectToAction(nameof(Login));
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
}
