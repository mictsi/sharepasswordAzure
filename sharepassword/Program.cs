using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using SharePassword.Data;
using SharePassword.Options;
using SharePassword.Services;

if (AdminPasswordHashCli.TryRun(args))
{
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

builder.Services
    .AddOptions<ApplicationOptions>()
    .Bind(builder.Configuration.GetSection(ApplicationOptions.SectionName))
    .Validate(
        options => ApplicationOptions.IsValidPathBase(options.PathBase),
        "Application:PathBase must be '/' or a relative path like '/sharepassword'.")
    .Validate(
        options => ApplicationOptions.IsValidTimeZoneId(options.TimeZoneId),
        "Application:TimeZoneId must be a valid Windows or IANA time zone ID available on the host.")
    .Validate(
        options => options.AuthenticationSessionTimeoutMinutes > 0,
        "Application:AuthenticationSessionTimeoutMinutes must be greater than 0.")
    .ValidateOnStart();

builder.Services
    .AddOptions<AdminAuthOptions>()
    .Bind(builder.Configuration.GetSection(AdminAuthOptions.SectionName))
    .Validate(
        options => !string.IsNullOrWhiteSpace(options.PasswordHash),
        "AdminAuth:PasswordHash is required.")
    .Validate(
        options => string.IsNullOrWhiteSpace(options.PasswordHash) || AdminPasswordHash.IsValid(options.PasswordHash),
        "AdminAuth:PasswordHash must use a supported hash format. Preferred: ARGON2ID$v=19$m=<memory-kib>,t=<iterations>,p=<parallelism>$<salt-base64>$<hash-base64>; fallback: SCRYPT$N=<cost>,r=<block-size>,p=<parallelism>$<salt-base64>$<hash-base64>; legacy PBKDF2 values remain valid.")
    .ValidateOnStart();
builder.Services
    .AddOptions<DatabaseResilienceOptions>()
    .Bind(builder.Configuration.GetSection(DatabaseResilienceOptions.SectionName))
    .Validate(options => options.MaxAttempts > 0, "DatabaseResilience:MaxAttempts must be greater than 0.")
    .Validate(options => options.DelayMilliseconds >= 0, "DatabaseResilience:DelayMilliseconds must be 0 or greater.")
    .ValidateOnStart();
builder.Services.Configure<EncryptionOptions>(builder.Configuration.GetSection(EncryptionOptions.SectionName));
builder.Services.Configure<ShareOptions>(builder.Configuration.GetSection(ShareOptions.SectionName));
builder.Services.Configure<OidcAuthOptions>(builder.Configuration.GetSection(OidcAuthOptions.SectionName));
builder.Services.Configure<ConsoleAuditLoggingOptions>(builder.Configuration.GetSection(ConsoleAuditLoggingOptions.SectionName));
builder.Services.AddAntiforgery();
builder.Services
    .AddOptions<AntiforgeryOptions>()
    .Configure<IOptions<ApplicationOptions>>((options, applicationOptionsAccessor) =>
    {
        var normalizedPathBase = ApplicationOptions.NormalizePathBase(applicationOptionsAccessor.Value.PathBase);
        options.Cookie.Path = string.IsNullOrEmpty(normalizedPathBase) ? "/" : normalizedPathBase;
    });

builder.Services.AddControllersWithViews();
builder.Services.AddSingleton<IDatabaseExceptionMapper, DatabaseExceptionMapper>();
builder.Services.AddSingleton<IDatabaseOperationRunner, DatabaseOperationRunner>();
builder.Services.AddSingleton<IApplicationTime, ApplicationTime>();
builder.Services.AddConfiguredStorageBackend(builder.Configuration);
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseConnectivityHealthCheck>("database");

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
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });

builder.Services
    .AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<IOptions<ApplicationOptions>>((options, applicationOptionsAccessor) =>
    {
        var applicationOptions = applicationOptionsAccessor.Value;
        var normalizedPathBase = ApplicationOptions.NormalizePathBase(applicationOptions.PathBase);

        options.ExpireTimeSpan = TimeSpan.FromMinutes(applicationOptions.AuthenticationSessionTimeoutMinutes);
        options.SlidingExpiration = applicationOptions.AuthenticationSlidingExpiration;
        options.Cookie.Path = string.IsNullOrEmpty(normalizedPathBase) ? "/" : normalizedPathBase;
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
                var usageMetricsService = context.HttpContext.RequestServices.GetService<IUsageMetricsService>();
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

                if (usageMetricsService is not null)
                {
                    var metricKey = string.Equals(actorType, "admin", StringComparison.OrdinalIgnoreCase)
                        ? DbUsageMetricsService.AdminLoginKey
                        : DbUsageMetricsService.UserLoginKey;
                    await usageMetricsService.RecordAsync(metricKey, actorType, actor, details: "OIDC sign-in succeeded.");
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
    options.AddPolicy("AuditAccess", policy => policy.RequireRole(adminRoleName, BuiltInRoleNames.Auditor));
});
builder.Services.AddHttpContextAccessor();

builder.Services.AddScoped<IPasswordCryptoService, PasswordCryptoService>();
builder.Services.AddScoped<IAccessCodeService, AccessCodeService>();
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
builder.Services.AddHostedService<ExpiredShareCleanupService>();

var app = builder.Build();
var runtimeApplicationOptions = app.Services.GetRequiredService<IOptions<ApplicationOptions>>().Value;
var normalizedPathBase = ApplicationOptions.NormalizePathBase(runtimeApplicationOptions.PathBase);
var startupLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
var runtimeStorageOptions = app.Services.GetRequiredService<IOptions<StorageOptions>>().Value;
var runtimeDatabaseResilienceOptions = app.Services.GetRequiredService<IOptions<DatabaseResilienceOptions>>().Value;
var storageBackend = StorageOptions.NormalizeBackend(runtimeStorageOptions.Backend);

startupLogger.LogInformation(
    "Storage backend {StorageBackend} configured. Database operations will use up to {MaxAttempts} attempts with {DelayMilliseconds} ms delay between attempts.",
    storageBackend,
    Math.Max(1, runtimeDatabaseResilienceOptions.MaxAttempts),
    Math.Max(0, runtimeDatabaseResilienceOptions.DelayMilliseconds));

try
{
    await app.Services.ApplyConfiguredStorageMigrationsAsync();
    startupLogger.LogInformation("Database startup checks completed successfully for backend {StorageBackend}.", storageBackend);

    await app.Services.GetRequiredService<IPlatformInitializationService>().InitializeAsync();
    startupLogger.LogInformation("Platform initialization completed successfully.");
}
catch (DatabaseOperationException exception)
{
    startupLogger.LogCritical(exception, "Database startup failed for backend {StorageBackend}. {DiagnosticMessage}", storageBackend, exception.DiagnosticMessage);
    throw;
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

if (runtimeApplicationOptions.EnableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

if (!string.IsNullOrEmpty(normalizedPathBase))
{
    app.UsePathBase(normalizedPathBase);
}

app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

    await next();
});

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapHealthChecks("/health");

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
