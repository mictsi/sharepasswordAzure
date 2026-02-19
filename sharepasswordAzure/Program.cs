using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Azure.Core;
using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
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

builder.Services.AddControllersWithViews();

var oidcOptions = builder.Configuration.GetSection(OidcAuthOptions.SectionName).Get<OidcAuthOptions>() ?? new OidcAuthOptions();

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
    });
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireAuthenticatedUser());
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
