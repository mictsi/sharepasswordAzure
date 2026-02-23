using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Azure.Core;
using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using SharePassword.Options;
using SharePassword.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

builder.Services.Configure<AdminAuthOptions>(builder.Configuration.GetSection(AdminAuthOptions.SectionName));
builder.Services.Configure<EncryptionOptions>(builder.Configuration.GetSection(EncryptionOptions.SectionName));
builder.Services.Configure<ShareOptions>(builder.Configuration.GetSection(ShareOptions.SectionName));
builder.Services.Configure<AzureTableAuditOptions>(builder.Configuration.GetSection(AzureTableAuditOptions.SectionName));
builder.Services.Configure<OidcAuthOptions>(builder.Configuration.GetSection(OidcAuthOptions.SectionName));
builder.Services.Configure<AzureKeyVaultOptions>(builder.Configuration.GetSection(AzureKeyVaultOptions.SectionName));
builder.Services.Configure<ConsoleAuditLoggingOptions>(builder.Configuration.GetSection(ConsoleAuditLoggingOptions.SectionName));

builder.Services.AddControllersWithViews();

var oidcOptions = builder.Configuration.GetSection(OidcAuthOptions.SectionName).Get<OidcAuthOptions>() ?? new OidcAuthOptions();
var adminRoleName = string.IsNullOrWhiteSpace(oidcOptions.AdminRoleName) ? "Admin" : oidcOptions.AdminRoleName.Trim();
var userRoleName = string.IsNullOrWhiteSpace(oidcOptions.UserRoleName) ? "User" : oidcOptions.UserRoleName.Trim();

var authenticationBuilder = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = oidcOptions.Enabled ? OpenIdConnectDefaults.AuthenticationScheme : CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/account/login";
        options.LogoutPath = "/account/logout";
        options.AccessDeniedPath = "/account/login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.Cookie.MaxAge = TimeSpan.FromMinutes(60);
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

if (oidcOptions.Enabled)
{
    if (string.IsNullOrWhiteSpace(oidcOptions.Authority) || string.IsNullOrWhiteSpace(oidcOptions.ClientId))
    {
        throw new InvalidOperationException("OIDC is enabled but Authority/ClientId are not configured.");
    }

    authenticationBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = oidcOptions.Authority;
        options.ClientId = oidcOptions.ClientId;
        options.ClientSecret = oidcOptions.ClientSecret;
        options.CallbackPath = oidcOptions.CallbackPath;
        options.SignedOutCallbackPath = oidcOptions.SignedOutCallbackPath;
        options.RequireHttpsMetadata = oidcOptions.RequireHttpsMetadata;
        options.ResponseType = "code";
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;

        options.Scope.Clear();
        foreach (var scope in oidcOptions.Scopes)
        {
            options.Scope.Add(scope);
        }

        options.Events.OnTokenValidated = context =>
        {
            if (context.Principal?.Identity is not ClaimsIdentity identity)
            {
                return Task.CompletedTask;
            }

            var externalRoleClaims = context.Principal.Claims
                .Where(claim => string.Equals(claim.Type, "roles", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(claim.Type, "role", StringComparison.OrdinalIgnoreCase))
                .Select(claim => claim.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var externalRole in externalRoleClaims)
            {
                if (!identity.HasClaim(ClaimTypes.Role, externalRole))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, externalRole));
                }
            }

            var stableIdentifier = context.Principal.FindFirst("oid")?.Value
                ?? context.Principal.FindFirst("sub")?.Value;
            if (!string.IsNullOrWhiteSpace(stableIdentifier) && !identity.HasClaim(ClaimTypes.NameIdentifier, stableIdentifier))
            {
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, stableIdentifier));
            }

            var preferredUsername = context.Principal.FindFirst("preferred_username")?.Value
                ?? context.Principal.FindFirst("upn")?.Value
                ?? context.Principal.FindFirst("email")?.Value;
            if (!string.IsNullOrWhiteSpace(preferredUsername))
            {
                if (!identity.HasClaim(ClaimTypes.Name, preferredUsername))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, preferredUsername));
                }

                if (preferredUsername.Contains('@') && !identity.HasClaim(ClaimTypes.Email, preferredUsername))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Email, preferredUsername));
                }
            }

            var groupClaimType = string.IsNullOrWhiteSpace(oidcOptions.GroupClaimType) ? "groups" : oidcOptions.GroupClaimType.Trim();
            var principalGroups = context.Principal.Claims
                .Where(claim => string.Equals(claim.Type, groupClaimType, StringComparison.OrdinalIgnoreCase))
                .Select(claim => claim.Value)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var adminGroups = oidcOptions.AdminGroups
                .Where(group => !string.IsNullOrWhiteSpace(group))
                .Select(group => group.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var userGroups = oidcOptions.UserGroups
                .Where(group => !string.IsNullOrWhiteSpace(group))
                .Select(group => group.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (principalGroups.Overlaps(adminGroups) && !identity.HasClaim(ClaimTypes.Role, adminRoleName))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, adminRoleName));
            }

            if (principalGroups.Overlaps(userGroups) && !identity.HasClaim(ClaimTypes.Role, userRoleName))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, userRoleName));
            }

            if (identity.HasClaim(ClaimTypes.Role, adminRoleName) && !identity.HasClaim(ClaimTypes.Role, userRoleName))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, userRoleName));
            }

            return Task.CompletedTask;
        };

        options.Events.OnTicketReceived = async context =>
        {
            try
            {
                var role = context.Principal?.FindFirst(ClaimTypes.Role)?.Value;
                var actorType = string.Equals(role, adminRoleName, StringComparison.OrdinalIgnoreCase)
                    ? "admin"
                    : string.Equals(role, userRoleName, StringComparison.OrdinalIgnoreCase)
                        ? "user"
                        : "oidc-user";

                var actor = context.Principal?.FindFirst("preferred_username")?.Value
                    ?? context.Principal?.FindFirst("email")?.Value
                    ?? context.Principal?.FindFirst(ClaimTypes.Email)?.Value
                    ?? context.Principal?.FindFirst("upn")?.Value
                    ?? context.Principal?.FindFirst("unique_name")?.Value
                    ?? context.Principal?.FindFirst("name")?.Value
                    ?? context.Principal?.FindFirst(ClaimTypes.Name)?.Value
                    ?? context.Principal?.Identity?.Name
                    ?? context.Principal?.FindFirst("oid")?.Value
                    ?? "unknown";

                var auditLogger = context.HttpContext.RequestServices.GetService<IAuditLogger>();
                if (auditLogger is null)
                {
                    return;
                }

                if (oidcOptions.LogTokensForTroubleshooting)
                {
                    var idToken = context.Properties?.GetTokenValue("id_token") ?? "(missing)";
                    var accessToken = context.Properties?.GetTokenValue("access_token") ?? "(missing)";
                    var refreshToken = context.Properties?.GetTokenValue("refresh_token") ?? "(missing)";

                    await auditLogger.LogAsync(
                        actorType,
                        actor,
                        "oidc.login.success",
                        true,
                        details: $"OIDC login succeeded. role={role ?? "(none)"}. id_token={idToken}; access_token={accessToken}; refresh_token={refreshToken}");
                }
                else
                {
                    await auditLogger.LogAsync(
                        actorType,
                        actor,
                        "oidc.login.success",
                        true,
                        details: $"OIDC login succeeded. role={role ?? "(none)"}.");
                }
            }
            catch
            {
            }
        };

        options.Events.OnAuthenticationFailed = async context =>
        {
            try
            {
                var auditLogger = context.HttpContext.RequestServices.GetService<IAuditLogger>();
                if (auditLogger is not null)
                {
                    await auditLogger.LogAsync(
                        "admin",
                        "unknown",
                        "oidc.login.failed",
                        false,
                        details: context.Exception?.Message ?? "OIDC authentication failed.");
                }
            }
            catch
            {
            }
        };

        options.Events.OnRemoteFailure = async context =>
        {
            try
            {
                var auditLogger = context.HttpContext.RequestServices.GetService<IAuditLogger>();
                if (auditLogger is not null)
                {
                    await auditLogger.LogAsync(
                        "admin",
                        "unknown",
                        "oidc.login.failed",
                        false,
                        details: context.Failure?.Message ?? "OIDC remote failure.");
                }
            }
            catch
            {
            }
        };
    });
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(adminRoleName));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole(adminRoleName, userRoleName));
});

builder.Services.AddHttpContextAccessor();

builder.Services.AddSingleton(provider =>
{
    var options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value;
    if (string.IsNullOrWhiteSpace(options.VaultUri))
    {
        throw new InvalidOperationException("AzureKeyVault:VaultUri must be configured.");
    }

    TokenCredential credential;
    if (!string.IsNullOrWhiteSpace(options.TenantId)
        && !string.IsNullOrWhiteSpace(options.ClientId)
        && !string.IsNullOrWhiteSpace(options.ClientSecret))
    {
        credential = new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret);
    }
    else
    {
        credential = new DefaultAzureCredential();
    }

    return new SecretClient(new Uri(options.VaultUri), credential);
});

builder.Services.AddSingleton(provider =>
{
    var options = provider.GetRequiredService<IOptions<AzureTableAuditOptions>>().Value;
    if (string.IsNullOrWhiteSpace(options.ServiceSasUrl))
    {
        throw new InvalidOperationException("AzureTableAudit:ServiceSasUrl must be configured.");
    }

    return new TableServiceClient(new Uri(options.ServiceSasUrl));
});

builder.Services.AddScoped<IPasswordCryptoService, PasswordCryptoService>();
builder.Services.AddScoped<IAccessCodeService, AccessCodeService>();
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
builder.Services.AddSingleton<KeyVaultStore>();
builder.Services.AddSingleton<IShareStore>(provider => provider.GetRequiredService<KeyVaultStore>());
builder.Services.AddSingleton<AuditTableStore>();
builder.Services.AddSingleton<IAuditLogReader>(provider => provider.GetRequiredService<AuditTableStore>());
builder.Services.AddSingleton<IAuditLogSink>(provider => provider.GetRequiredService<AuditTableStore>());
builder.Services.AddHostedService<ExpiredShareCleanupService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

if (builder.Configuration.GetValue("Application:EnableHttpsRedirection", false))
{
    app.UseHttpsRedirection();
}
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "share-link",
    pattern: "s/{token}",
    defaults: new { controller = "Share", action = "Access" })
    .WithStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Admin}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();

public partial class Program;
