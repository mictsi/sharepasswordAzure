using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OtpNet;
using SharePassword.Data;
using SharePassword.Models;
using SharePassword.Services;

namespace SharePassword.Tests;

internal static class TestAdminAuth
{
    public const string Username = "admin";
    public const string Password = "admin123!ChangeMe";
    public static string PasswordHash { get; } = AdminPasswordHash.Create(Password);
}

public class WebIntegrationTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public WebIntegrationTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Get_AdminLogin_ReturnsSuccess()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/account/login");
        var content = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Contains("Admin Login", content, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminLogin_SetsSessionCookie_WithoutPersistentExpiry()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        var loginPageResponse = await client.GetAsync("/account/login");
        var loginPage = await loginPageResponse.Content.ReadAsStringAsync();
        var antiForgery = ExtractAntiForgeryToken(loginPage);

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = TestAdminAuth.Password
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        Assert.True(loginResponse.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));

        var authCookie = cookieHeaders.FirstOrDefault(x => x.StartsWith(".AspNetCore.Cookies=", StringComparison.Ordinal));
        Assert.False(string.IsNullOrWhiteSpace(authCookie));
        Assert.DoesNotContain("expires=", authCookie!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", authCookie!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminLogin_WithPasswordHashOnly_Succeeds()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        var loginPage = await client.GetAsync("/account/login");
        var loginHtml = await loginPage.Content.ReadAsStringAsync();
        var antiForgery = ExtractAntiForgeryToken(loginHtml);

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = TestAdminAuth.Password
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
    }

    [Fact]
    public async Task AdminLogin_WhenOidcDisabled_AllowsRemotePasswordLogin()
    {
        await using var factory = new RemoteIpWebApplicationFactory(
            new Dictionary<string, string?>
            {
                ["OidcAuth:Enabled"] = "false"
            },
            IPAddress.Parse("203.0.113.10"));

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        var loginPageResponse = await client.GetAsync("/account/login");
        var loginPage = await loginPageResponse.Content.ReadAsStringAsync();
        var antiForgery = ExtractAntiForgeryToken(loginPage);

        loginPageResponse.EnsureSuccessStatusCode();

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = TestAdminAuth.Password
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, loginResponse.StatusCode);
    }

    [Fact]
    public async Task ConfiguredPathBase_AndAuthenticationSessionSettings_AreApplied()
    {
        const string pathBase = "/published-app";

        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>
        {
            ["Application:PathBase"] = pathBase,
            ["Application:AuthenticationSessionTimeoutMinutes"] = "25",
            ["Application:AuthenticationSlidingExpiration"] = "false"
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        var cookieOptionsMonitor = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        var cookieOptions = cookieOptionsMonitor.Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal(TimeSpan.FromMinutes(25), cookieOptions.ExpireTimeSpan);
        Assert.False(cookieOptions.SlidingExpiration);
        Assert.Equal(pathBase, cookieOptions.Cookie.Path);

        var loginPath = CombineAppPath(pathBase, "/account/login");
        var loginPageResponse = await client.GetAsync(loginPath);
        var loginPage = await loginPageResponse.Content.ReadAsStringAsync();
        var antiForgery = ExtractAntiForgeryToken(loginPage);

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, loginPath)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = TestAdminAuth.Password
            })
        };

        loginRequest.Headers.Referrer = new Uri($"https://localhost{loginPath}");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        Assert.True(loginResponse.Headers.TryGetValues("Set-Cookie", out var cookieHeaders));

        var authCookie = cookieHeaders.FirstOrDefault(x => x.StartsWith(".AspNetCore.Cookies=", StringComparison.Ordinal));
        Assert.False(string.IsNullOrWhiteSpace(authCookie));
        Assert.DoesNotContain("expires=", authCookie!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", authCookie!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"path={pathBase}", authCookie!, StringComparison.OrdinalIgnoreCase);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "basepath.user", "BasePathPassword!123", pathBase);

        Assert.StartsWith($"{pathBase}/s/", created.SharePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ConfiguredTimeZone_IsShownInAdminCreatePage()
    {
        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>
        {
            ["Application:TimeZoneId"] = "Europe/Stockholm"
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var html = await client.GetStringAsync("/admin/create");
        var applicationTime = factory.Services.GetRequiredService<IApplicationTime>();

        Assert.Contains(applicationTime.TimeZoneId, html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminCreate_WhenOidcDisabled_RendersRequireOidcLoginReadOnly()
    {
        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>
        {
            ["OidcAuth:Enabled"] = "false"
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var html = await client.GetStringAsync("/admin/create");
        var input = ExtractInputById(html, "RequireOidcLogin");

        Assert.Contains("disabled=\"disabled\"", input, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("aria-disabled=\"true\"", input, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Microsoft Entra ID sign-in is disabled in application configuration.", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminCreate_WhenOidcEnabled_RendersRequireOidcLoginEditable()
    {
        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>
        {
            ["OidcAuth:Enabled"] = "true"
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var html = await client.GetStringAsync("/admin/create");
        var input = ExtractInputById(html, "RequireOidcLogin");

        Assert.DoesNotContain("disabled=", input, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Require the signed-in Microsoft Entra ID account to match the recipient email before the access code can be used.", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminCreate_LoadsJQueryCompatibilityBeforeUnobtrusiveValidation()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var html = await client.GetStringAsync("/admin/create");
        var compatibilityScriptIndex = html.IndexOf("/js/jquery-compat.js", StringComparison.OrdinalIgnoreCase);
        var unobtrusiveScriptIndex = html.IndexOf("/lib/jquery-validation-unobtrusive/dist/jquery.validate.unobtrusive.min.js", StringComparison.OrdinalIgnoreCase);

        Assert.True(compatibilityScriptIndex >= 0, "jQuery compatibility script was not rendered.");
        Assert.True(unobtrusiveScriptIndex >= 0, "jQuery unobtrusive validation script was not rendered.");
        Assert.True(compatibilityScriptIndex < unobtrusiveScriptIndex, "jQuery compatibility script must load before unobtrusive validation.");
    }

    [Fact]
    public async Task SecurityHeaders_AllowDataImagesForBootstrapFormControls()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/account/login");

        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var values));
        Assert.Contains("img-src 'self' data:", values.Single(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminCreate_WithClientEncryptedPayload_StoresOpaqueSecret()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"client-encrypted-{Guid.NewGuid():N}@example.com";
        const string plaintextSecret = "ThisShouldNeverBeStoredByServer";
        var encryptedPayload = CreateValidClientEncryptedPayload();
        var createPage = await client.GetStringAsync("/admin/create");
        var antiForgery = ExtractAntiForgeryToken(createPage);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/admin/create")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["RecipientEmail"] = recipientEmail,
                ["SharedUsername"] = "client.encrypted.user",
                ["Password"] = plaintextSecret,
                ["UseClientEncryption"] = "true",
                ["ClientEncryptedPasswordPayload"] = encryptedPayload,
                ["ExpiryHours"] = "4"
            })
        };

        createRequest.Headers.Referrer = new Uri("https://localhost/admin/create");
        var createResponse = await client.SendAsync(createRequest);
        var createHtml = await createResponse.Content.ReadAsStringAsync();

        createResponse.EnsureSuccessStatusCode();

        var shareStore = _factory.Services.GetRequiredService<IShareStore>();
        var share = (await shareStore.GetAllSharesAsync()).Single(x => x.RecipientEmail == recipientEmail);

        Assert.Equal(SecretEncryptionModes.ClientAesGcm, share.SecretEncryptionMode);
        Assert.Equal(encryptedPayload, share.EncryptedPassword);
        Assert.DoesNotContain(plaintextSecret, share.EncryptedPassword, StringComparison.Ordinal);

        var created = (ExtractSharePath(createHtml), ExtractAccessCode(createHtml));
        var accessResponse = await AccessShareAsync(client, created.Item1, recipientEmail, created.Item2);
        var credentialHtml = await accessResponse.Content.ReadAsStringAsync();

        accessResponse.EnsureSuccessStatusCode();
        Assert.Contains("Decrypt secret", credentialHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Extra password required", credentialHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(plaintextSecret, credentialHtml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdminCreate_WithClientEncryptionMissingPayload_RejectsShare()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"client-encrypted-missing-{Guid.NewGuid():N}@example.com";
        var createPage = await client.GetStringAsync("/admin/create");
        var antiForgery = ExtractAntiForgeryToken(createPage);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/admin/create")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["RecipientEmail"] = recipientEmail,
                ["SharedUsername"] = "client.encrypted.user",
                ["Password"] = "RejectedPlaintextSecret",
                ["UseClientEncryption"] = "true",
                ["ExpiryHours"] = "4"
            })
        };

        createRequest.Headers.Referrer = new Uri("https://localhost/admin/create");
        var createResponse = await client.SendAsync(createRequest);
        var createHtml = await createResponse.Content.ReadAsStringAsync();

        createResponse.EnsureSuccessStatusCode();
        Assert.Contains("must be encrypted in your browser", createHtml, StringComparison.OrdinalIgnoreCase);

        var shareStore = _factory.Services.GetRequiredService<IShareStore>();
        var shares = await shareStore.GetAllSharesAsync();

        Assert.DoesNotContain(shares, x => string.Equals(x.RecipientEmail, recipientEmail, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("RejectedPlaintextSecret", createHtml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UsersCreate_WithSelectedRole_CreatesLocalUser()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var username = $"local-{Guid.NewGuid():N}";
        var createPage = await client.GetStringAsync("/users/create");
        var antiForgery = ExtractAntiForgeryToken(createPage);

        Assert.Contains("data-generate-password", createPage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("data-password-strength=\"NewPassword\"", createPage, StringComparison.OrdinalIgnoreCase);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/users/create")
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("__RequestVerificationToken", antiForgery),
                new KeyValuePair<string, string>("Username", username),
                new KeyValuePair<string, string>("DisplayName", "Local User"),
                new KeyValuePair<string, string>("Email", $"{username}@example.com"),
                new KeyValuePair<string, string>("SelectedRoles", "User"),
                new KeyValuePair<string, string>("IsTotpRequired", "true"),
                new KeyValuePair<string, string>("NewPassword", "LocalPassword!123"),
                new KeyValuePair<string, string>("ConfirmPassword", "LocalPassword!123")
            ])
        };

        createRequest.Headers.Referrer = new Uri("https://localhost/users/create");
        var createResponse = await client.SendAsync(createRequest);
        var html = await createResponse.Content.ReadAsStringAsync();

        createResponse.EnsureSuccessStatusCode();
        Assert.Contains("User created.", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(username, html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("At least one built-in role must be selected.", html, StringComparison.OrdinalIgnoreCase);

        var localUserService = _factory.Services.GetRequiredService<ILocalUserService>();
        var createdUser = await localUserService.GetByUsernameAsync(username);
        Assert.NotNull(createdUser);
        Assert.True(createdUser.IsTotpRequired);
    }

    [Fact]
    public async Task UsersCreate_WithWeakPassword_ShowsValidationAndDoesNotCreateUser()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var username = $"weak-{Guid.NewGuid():N}";
        var createPage = await client.GetStringAsync("/users/create");
        var antiForgery = ExtractAntiForgeryToken(createPage);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/users/create")
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("__RequestVerificationToken", antiForgery),
                new KeyValuePair<string, string>("Username", username),
                new KeyValuePair<string, string>("DisplayName", "Weak User"),
                new KeyValuePair<string, string>("Email", $"{username}@example.com"),
                new KeyValuePair<string, string>("SelectedRoles", "User"),
                new KeyValuePair<string, string>("NewPassword", "weak"),
                new KeyValuePair<string, string>("ConfirmPassword", "weak")
            ])
        };

        createRequest.Headers.Referrer = new Uri("https://localhost/users/create");
        var createResponse = await client.SendAsync(createRequest);
        var html = await createResponse.Content.ReadAsStringAsync();

        createResponse.EnsureSuccessStatusCode();
        Assert.Contains("Password must be at least 12 characters long.", html, StringComparison.OrdinalIgnoreCase);

        var localUserService = _factory.Services.GetRequiredService<ILocalUserService>();
        var createdUser = await localUserService.GetByUsernameAsync(username);
        Assert.Null(createdUser);
    }

    [Fact]
    public async Task UsersResetPassword_WithPostedResetFields_UpdatesPassword()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var username = $"reset-{Guid.NewGuid():N}";
        const string oldPassword = "OldLocalPassword!123";
        const string newPassword = "NewLocalPassword!456";
        var localUserService = _factory.Services.GetRequiredService<ILocalUserService>();
        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "Reset User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = oldPassword
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        var editPage = await client.GetStringAsync($"/users/edit/{createResult.User!.Id}");
        Assert.Contains("name=\"UserId\"", editPage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"ResetPassword.UserId\"", editPage, StringComparison.OrdinalIgnoreCase);
        var antiForgery = ExtractAntiForgeryToken(editPage);

        var resetRequest = new HttpRequestMessage(HttpMethod.Post, "/users/resetpassword")
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("__RequestVerificationToken", antiForgery),
                new KeyValuePair<string, string>("UserId", createResult.User.Id.ToString()),
                new KeyValuePair<string, string>("Username", username),
                new KeyValuePair<string, string>("NewPassword", newPassword),
                new KeyValuePair<string, string>("ConfirmPassword", newPassword)
            ])
        };

        resetRequest.Headers.Referrer = new Uri($"https://localhost/users/edit/{createResult.User.Id}");
        var resetResponse = await client.SendAsync(resetRequest);
        var html = await resetResponse.Content.ReadAsStringAsync();

        resetResponse.EnsureSuccessStatusCode();
        Assert.Contains("Password reset.", html, StringComparison.OrdinalIgnoreCase);

        var oldPasswordAuthentication = await localUserService.AuthenticateAsync(username, oldPassword);
        var newPasswordAuthentication = await localUserService.AuthenticateAsync(username, newPassword);

        Assert.False(oldPasswordAuthentication.Succeeded);
        Assert.True(newPasswordAuthentication.Succeeded, newPasswordAuthentication.ErrorMessage);
    }

    [Fact]
    public async Task Profile_WithWeakNewPassword_ShowsValidationAndKeepsExistingPassword()
    {
        using var client = CreateClient();

        var username = $"profile-{Guid.NewGuid():N}";
        const string currentPassword = "ProfileCurrent!123";
        var localUserService = _factory.Services.GetRequiredService<ILocalUserService>();
        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "Profile User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = currentPassword
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        await LoginLocalUserAndFollowToHtmlAsync(client, username, currentPassword);
        var profilePage = await client.GetStringAsync("/account/profile");
        var antiForgery = ExtractAntiForgeryToken(profilePage);

        Assert.Contains("data-password-strength=\"NewPassword\"", profilePage, StringComparison.OrdinalIgnoreCase);

        var profileResponse = await client.PostAsync("/account/profile", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgery,
            ["CurrentPassword"] = currentPassword,
            ["NewPassword"] = "weak",
            ["ConfirmPassword"] = "weak"
        }));
        var html = await profileResponse.Content.ReadAsStringAsync();

        profileResponse.EnsureSuccessStatusCode();
        Assert.Contains("Password must be at least 12 characters long.", html, StringComparison.OrdinalIgnoreCase);

        var oldPasswordAuthentication = await localUserService.AuthenticateAsync(username, currentPassword);
        var weakPasswordAuthentication = await localUserService.AuthenticateAsync(username, "weak");

        Assert.True(oldPasswordAuthentication.Succeeded, oldPasswordAuthentication.ErrorMessage);
        Assert.False(weakPasswordAuthentication.Succeeded);
    }

    [Fact]
    public async Task LocalUser_WithRequiredTotp_CompletesAuthenticatorOnboardingBeforeSignIn()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        var localUserService = factory.Services.GetRequiredService<ILocalUserService>();
        var username = $"totp-required-{Guid.NewGuid():N}";
        const string password = "TotpRequired!123";

        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "TOTP Required User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = password,
            IsTotpRequired = true
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        var loginPage = await client.GetStringAsync("/account/login");
        var antiForgery = ExtractAntiForgeryToken(loginPage);
        var loginResponse = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgery,
            ["Username"] = username,
            ["Password"] = password
        }));
        var setupHtml = await loginResponse.Content.ReadAsStringAsync();

        loginResponse.EnsureSuccessStatusCode();
        Assert.Contains("Authenticator app setup", setupHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("data:image/png;base64,", setupHtml, StringComparison.OrdinalIgnoreCase);

        var manualKey = ExtractTotpManualKey(setupHtml);
        var setupCode = ComputeTotpCode(manualKey);
        var setupAntiForgery = ExtractAntiForgeryToken(setupHtml);

        var setupResponse = await client.PostAsync("/account/totpsetup", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = setupAntiForgery,
            ["Code"] = setupCode
        }));
        var dashboardHtml = await setupResponse.Content.ReadAsStringAsync();

        setupResponse.EnsureSuccessStatusCode();
        Assert.Contains("Password shares", dashboardHtml, StringComparison.OrdinalIgnoreCase);

        var configuredUser = await localUserService.GetByIdAsync(createResult.User!.Id);
        Assert.NotNull(configuredUser);
        Assert.NotNull(configuredUser.TotpConfirmedAtUtc);
        Assert.False(string.IsNullOrWhiteSpace(configuredUser.TotpSecretEncrypted));
        Assert.NotEqual(manualKey, configuredUser.TotpSecretEncrypted);
    }

    [Fact]
    public async Task TotpSetup_AfterConfirmation_ShowsReplacementSetupWithoutRevealingCurrentSecret()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        var localUserService = factory.Services.GetRequiredService<ILocalUserService>();
        var passwordCryptoService = factory.Services.GetRequiredService<IPasswordCryptoService>();
        var username = $"totp-change-{Guid.NewGuid():N}";
        const string password = "TotpChange!123";

        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "TOTP Change User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = password,
            IsTotpRequired = true
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        var initialSetupHtml = await LoginLocalUserAndFollowToHtmlAsync(client, username, password);
        var originalManualKey = ExtractTotpManualKey(initialSetupHtml);
        var initialSetupResponse = await client.PostAsync("/account/totpsetup", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiForgeryToken(initialSetupHtml),
            ["Code"] = ComputeTotpCode(originalManualKey)
        }));

        initialSetupResponse.EnsureSuccessStatusCode();

        var replacementHtml = await client.GetStringAsync("/account/totpsetup");
        var replacementManualKey = ExtractTotpManualKey(replacementHtml);

        Assert.Contains("Change authenticator app", replacementHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(originalManualKey, replacementHtml, StringComparison.Ordinal);
        Assert.NotEqual(originalManualKey, replacementManualKey);

        var userWithPendingReplacement = await localUserService.GetByIdAsync(createResult.User!.Id);
        Assert.NotNull(userWithPendingReplacement);
        Assert.Equal(originalManualKey, passwordCryptoService.Decrypt(userWithPendingReplacement.TotpSecretEncrypted));
        Assert.Equal(replacementManualKey, passwordCryptoService.Decrypt(userWithPendingReplacement.PendingTotpSecretEncrypted));

        var replacementResponse = await client.PostAsync("/account/totpsetup", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiForgeryToken(replacementHtml),
            ["Code"] = ComputeTotpCode(replacementManualKey)
        }));
        var replacementResponseHtml = await replacementResponse.Content.ReadAsStringAsync();

        replacementResponse.EnsureSuccessStatusCode();
        Assert.Contains("Authenticator app setup changed.", replacementResponseHtml, StringComparison.OrdinalIgnoreCase);

        var reloadedUser = await localUserService.GetByIdAsync(createResult.User.Id);
        Assert.NotNull(reloadedUser);
        Assert.Equal(replacementManualKey, passwordCryptoService.Decrypt(reloadedUser.TotpSecretEncrypted));
        Assert.Equal(string.Empty, reloadedUser.PendingTotpSecretEncrypted);
        Assert.NotEqual(originalManualKey, passwordCryptoService.Decrypt(reloadedUser.TotpSecretEncrypted));
    }

    [Fact]
    public async Task PlatformInitialization_EncryptsLegacyPlaintextTotpSecretsAtRest()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        var dbContextFactory = factory.Services.GetRequiredService<ISharePasswordDbContextFactory>();
        var localUserService = factory.Services.GetRequiredService<ILocalUserService>();
        var passwordCryptoService = factory.Services.GetRequiredService<IPasswordCryptoService>();
        var totpService = factory.Services.GetRequiredService<ITotpService>();
        var userId = Guid.NewGuid();
        var username = $"totp-legacy-{Guid.NewGuid():N}";
        var confirmedSecret = totpService.GenerateSecretKey();
        var pendingSecret = totpService.GenerateSecretKey();
        var now = DateTime.UtcNow;

        await using (var dbContext = await dbContextFactory.CreateDbContextAsync())
        {
            dbContext.LocalUsers.Add(new LocalUser
            {
                Id = userId,
                Username = username,
                DisplayName = "Legacy TOTP User",
                Email = $"{username}@example.com",
                PasswordHash = AdminPasswordHash.Create("TotpLegacy!123"),
                Roles = "User",
                IsDisabled = false,
                IsSeededAdmin = false,
                IsTotpRequired = true,
                TotpSecretEncrypted = confirmedSecret,
                TotpConfirmedAtUtc = now,
                PendingTotpSecretEncrypted = pendingSecret,
                PendingTotpCreatedAtUtc = now,
                CreatedAtUtc = now,
                UpdatedAtUtc = now,
                LastPasswordResetAtUtc = now
            });

            await dbContext.SaveChangesAsync();
        }

        await factory.Services.GetRequiredService<IPlatformInitializationService>().InitializeAsync();

        LocalUser? reloaded;
        await using (var dbContext = await dbContextFactory.CreateDbContextAsync())
        {
            reloaded = await dbContext.LocalUsers.FindAsync([userId]);
        }

        Assert.NotNull(reloaded);
        Assert.NotEqual(confirmedSecret, reloaded.TotpSecretEncrypted);
        Assert.NotEqual(pendingSecret, reloaded.PendingTotpSecretEncrypted);
        Assert.Equal(confirmedSecret, passwordCryptoService.Decrypt(reloaded.TotpSecretEncrypted));
        Assert.Equal(pendingSecret, passwordCryptoService.Decrypt(reloaded.PendingTotpSecretEncrypted));

        var verifyResult = await localUserService.VerifyTotpAsync(userId, ComputeTotpCode(confirmedSecret), TestAdminAuth.Username);
        Assert.True(verifyResult.Succeeded, verifyResult.ErrorMessage);
    }

    [Fact]
    public async Task TotpSetup_DuringPendingLogin_WithConfirmedTotp_RedirectsToVerification()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        var localUserService = factory.Services.GetRequiredService<ILocalUserService>();
        var username = $"totp-pending-{Guid.NewGuid():N}";
        const string password = "TotpPending!123";

        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "TOTP Pending User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = password,
            IsTotpRequired = true
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        var setupResult = await localUserService.EnsureTotpSetupAsync(createResult.User!.Id, TestAdminAuth.Username);
        Assert.True(setupResult.Succeeded, setupResult.ErrorMessage);
        Assert.NotNull(setupResult.Setup);

        var confirmResult = await localUserService.ConfirmTotpAsync(createResult.User.Id, ComputeTotpCode(setupResult.Setup.SecretKey), TestAdminAuth.Username);
        Assert.True(confirmResult.Succeeded, confirmResult.ErrorMessage);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        var loginPage = await client.GetStringAsync("/account/login");
        var loginResponse = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiForgeryToken(loginPage),
            ["Username"] = username,
            ["Password"] = password
        }));

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        Assert.Contains("/Account/Totp", loginResponse.Headers.Location?.OriginalString ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        var setupAttempt = await client.GetAsync("/account/totpsetup");

        Assert.Equal(HttpStatusCode.Redirect, setupAttempt.StatusCode);
        Assert.Contains("/Account/Totp", setupAttempt.Headers.Location?.OriginalString ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UsersRemoveTotp_ClearsLocalUserAuthenticatorSetup()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        var localUserService = factory.Services.GetRequiredService<ILocalUserService>();
        var username = $"totp-reset-{Guid.NewGuid():N}";

        var createResult = await localUserService.CreateAsync(new LocalUserUpsertRequest
        {
            Username = username,
            DisplayName = "TOTP Reset User",
            Email = $"{username}@example.com",
            Roles = ["User"],
            Password = "TotpReset!123",
            IsTotpRequired = true
        }, TestAdminAuth.Username);

        Assert.True(createResult.Succeeded, createResult.ErrorMessage);

        var setupResult = await localUserService.EnsureTotpSetupAsync(createResult.User!.Id, TestAdminAuth.Username);
        Assert.True(setupResult.Succeeded, setupResult.ErrorMessage);
        Assert.NotNull(setupResult.Setup);

        var confirmResult = await localUserService.ConfirmTotpAsync(createResult.User.Id, ComputeTotpCode(setupResult.Setup.SecretKey), TestAdminAuth.Username);
        Assert.True(confirmResult.Succeeded, confirmResult.ErrorMessage);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var editPage = await client.GetStringAsync($"/users/edit/{createResult.User.Id}");
        Assert.Contains("Authenticator app", editPage, StringComparison.OrdinalIgnoreCase);
        var antiForgery = ExtractAntiForgeryToken(editPage);

        var resetResponse = await client.PostAsync($"/users/removetotp/{createResult.User.Id}", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgery
        }));
        var resetHtml = await resetResponse.Content.ReadAsStringAsync();

        resetResponse.EnsureSuccessStatusCode();
        Assert.Contains("Authenticator app setup reset.", resetHtml, StringComparison.OrdinalIgnoreCase);

        var reloaded = await localUserService.GetByIdAsync(createResult.User.Id);
        Assert.NotNull(reloaded);
        Assert.Equal(string.Empty, reloaded.TotpSecretEncrypted);
        Assert.Null(reloaded.TotpConfirmedAtUtc);
        Assert.Null(reloaded.LastTotpTimeStepMatched);
        Assert.Equal(string.Empty, reloaded.PendingTotpSecretEncrypted);
        Assert.Null(reloaded.PendingTotpCreatedAtUtc);
        Assert.True(reloaded.IsTotpRequired);
    }

    [Fact]
    public async Task Get_Health_ReturnsSuccess()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/health");

        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task AdminDashboard_CurrentShares_RendersScalableMetadataList()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string sharedUsername = "dashboard.user";
        await CreateShareAsync(client, recipientEmail, sharedUsername, "DashboardPassword!123");

        var dashboardHtml = await client.GetStringAsync("/admin");

        Assert.Contains("share-list", dashboardHtml, StringComparison.Ordinal);
        Assert.Contains("CREATED ON", dashboardHtml, StringComparison.Ordinal);
        Assert.Contains("EXPIRES ON", dashboardHtml, StringComparison.Ordinal);
        Assert.Contains("Created by", dashboardHtml, StringComparison.Ordinal);
        Assert.Contains("ACCESS MODE", dashboardHtml, StringComparison.Ordinal);
        Assert.Contains(recipientEmail, dashboardHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(sharedUsername, dashboardHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("share-card-grid", dashboardHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Created (", dashboardHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Expires (", dashboardHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch("data-label=\"CREATED ON\"[\\s\\S]*?share-list__value\">[^<]*UTC", dashboardHtml);
        Assert.DoesNotMatch("data-label=\"EXPIRES ON\"[\\s\\S]*?share-list__value\">[^<]*UTC", dashboardHtml);
    }

    [Fact]
    public async Task AdminCanCreateShare_ExternalUserCanAccessWithEmailAndCode()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string sharedUsername = "external.user";
        const string sharedPassword = "S3cur3Password!";

        var created = await CreateShareAsync(client, recipientEmail, sharedUsername, sharedPassword);
        var accessResponse = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var accessHtml = await accessResponse.Content.ReadAsStringAsync();

        accessResponse.EnsureSuccessStatusCode();
        Assert.Contains("Shared Credentials", accessHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(sharedUsername, accessHtml, StringComparison.Ordinal);
        Assert.Contains(sharedPassword, accessHtml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ShareAccess_FailedAttemptsPauseOnlyThatShare_UsingConfiguredSettings()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var settingsPage = await client.GetStringAsync("/configuration/settings");
        Assert.Contains("ShareAccessFailedAttemptLimit", settingsPage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ShareAccessPauseMinutes", settingsPage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Save time display", settingsPage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Save share access pause", settingsPage, StringComparison.OrdinalIgnoreCase);
        var settingsAntiForgery = ExtractAntiForgeryToken(settingsPage);

        var settingsResponse = await client.PostAsync("/configuration/saveshareaccesspause", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = settingsAntiForgery,
            ["ShareAccessPause.ShareAccessFailedAttemptLimit"] = "2",
            ["ShareAccessPause.ShareAccessPauseMinutes"] = "5"
        }));
        var settingsHtml = await settingsResponse.Content.ReadAsStringAsync();

        settingsResponse.EnsureSuccessStatusCode();
        Assert.Contains("Share access pause settings saved.", settingsHtml, StringComparison.OrdinalIgnoreCase);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "locked.share", "LockedSharePassword!123");
        var wrongCode = string.Equals(created.AccessCode, "AAAAAAAAAA", StringComparison.Ordinal) ? "BBBBBBBBBB" : "AAAAAAAAAA";

        var firstFailure = await AccessShareAsync(client, created.SharePath, recipientEmail, wrongCode);
        var firstFailureHtml = await firstFailure.Content.ReadAsStringAsync();
        firstFailure.EnsureSuccessStatusCode();
        Assert.Contains("Invalid link or access details.", firstFailureHtml, StringComparison.OrdinalIgnoreCase);

        var secondFailure = await AccessShareAsync(client, created.SharePath, recipientEmail, wrongCode);
        var secondFailureHtml = await secondFailure.Content.ReadAsStringAsync();
        secondFailure.EnsureSuccessStatusCode();
        Assert.Contains("Too many failed attempts for this share.", secondFailureHtml, StringComparison.OrdinalIgnoreCase);

        var blockedSuccess = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var blockedSuccessHtml = await blockedSuccess.Content.ReadAsStringAsync();
        blockedSuccess.EnsureSuccessStatusCode();
        Assert.Contains("Too many failed attempts for this share.", blockedSuccessHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LockedSharePassword!123", blockedSuccessHtml, StringComparison.Ordinal);

        var shareStore = factory.Services.GetRequiredService<IShareStore>();
        var lockedShare = await shareStore.GetShareByTokenAsync(ExtractShareTokenFromPath(created.SharePath));
        Assert.NotNull(lockedShare);
        Assert.Equal(2, lockedShare.FailedAccessAttempts);
        Assert.NotNull(lockedShare.AccessPausedUntilUtc);
    }

    [Fact]
    public async Task AdminCanCreateShare_WithMultilineYamlJsonAndSpecialText_PreservesExactValue()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string sharedUsername = "external.user";
        var prefix = "plain text line 1\nline 2 with symbols !@#$%^&*()[]{}<>\\\"'\n---\nkey: value\nlist:\n  - one\n  - two\n{\"json\":true,\"count\":2}\n";
        var secret = prefix + new string('x', 1000 - prefix.Length);

        var created = await CreateShareAsync(client, recipientEmail, sharedUsername, secret);
        var accessResponse = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var accessHtml = await accessResponse.Content.ReadAsStringAsync();

        accessResponse.EnsureSuccessStatusCode();

        var textareaMatch = Regex.Match(
            accessHtml,
            "<textarea[^>]*readonly[^>]*>(?<secret>.*?)</textarea>",
            RegexOptions.Singleline | RegexOptions.IgnoreCase);

        Assert.True(textareaMatch.Success, "Readonly secret textarea was not found.");

        var decodedSecret = WebUtility.HtmlDecode(textareaMatch.Groups["secret"].Value);
        Assert.Equal(secret, decodedSecret);
    }

    [Fact]
    public async Task ExternalUserCanDeleteRetrievedPassword_AfterViewingCredential()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string sharedUsername = "external.user";
        const string sharedPassword = "S3cur3Password!";

        var created = await CreateShareAsync(client, recipientEmail, sharedUsername, sharedPassword);
        var accessResponse = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var credentialHtml = await accessResponse.Content.ReadAsStringAsync();

        accessResponse.EnsureSuccessStatusCode();

        var antiForgery = ExtractAntiForgeryToken(credentialHtml);
        var shareId = ExtractShareIdFromCredentialPage(credentialHtml);

        var deleteRequest = new HttpRequestMessage(HttpMethod.Post, "/share/deleteafterretrieve")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["ShareId"] = shareId,
                ["RecipientEmail"] = recipientEmail
            })
        };

        deleteRequest.Headers.Referrer = new Uri($"https://localhost{created.SharePath}");
        var deleteResponse = await client.SendAsync(deleteRequest);
        var deleteHtml = await deleteResponse.Content.ReadAsStringAsync();

        deleteResponse.EnsureSuccessStatusCode();
        Assert.Contains("Password Deleted", deleteHtml, StringComparison.OrdinalIgnoreCase);

        var secondAccess = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var secondAccessHtml = await secondAccess.Content.ReadAsStringAsync();

        secondAccess.EnsureSuccessStatusCode();
        Assert.Contains("Invalid link or access details.", secondAccessHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminLoginFailure_IsAudited()
    {
        using var client = CreateClient();

        var loginPage = await client.GetStringAsync("/account/login");
        var antiForgery = ExtractAntiForgeryToken(loginPage);

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = "wrong-password"
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var response = await client.SendAsync(loginRequest);
        var html = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Contains("Invalid login attempt.", html, StringComparison.OrdinalIgnoreCase);

        await LoginAsAdminAsync(client);
        var auditHtml = await client.GetStringAsync("/admin/audit");
        Assert.Contains("admin.login", auditHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Invalid login attempt.", auditHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AuditLogs_CanBeFilteredByDateRange()
    {
        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>());
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        var auditStore = factory.Services.GetRequiredService<InMemoryAuditStore>();
        await auditStore.AddAuditAsync(new AuditLog
        {
            TimestampUtc = DateTime.UtcNow.AddMonths(-7),
            ActorType = "admin",
            ActorIdentifier = "old-admin",
            Operation = "share.create",
            Success = true,
            Details = "Too old"
        });
        await auditStore.AddAuditAsync(new AuditLog
        {
            TimestampUtc = DateTime.UtcNow.AddDays(-3),
            ActorType = "admin",
            ActorIdentifier = "recent-admin",
            Operation = "share.revoke",
            Success = true,
            Details = "Recent enough"
        });

        await LoginAsAdminAsync(client);

        var filteredHtml = await client.GetStringAsync("/admin/audit?range=last-6-months");

        Assert.Contains("recent-admin", filteredHtml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("old-admin", filteredHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AuditLogs_CanBeExportedAsJson()
    {
        await using var factory = new ConfiguredApplicationWebApplicationFactory(new Dictionary<string, string?>());
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        var auditStore = factory.Services.GetRequiredService<InMemoryAuditStore>();
        await auditStore.AddAuditAsync(new AuditLog
        {
            TimestampUtc = DateTime.UtcNow,
            ActorType = "admin",
            ActorIdentifier = "export-admin",
            Operation = "share.create",
            Success = true,
            Details = "Export me"
        });

        await LoginAsAdminAsync(client);

        var response = await client.GetAsync("/admin/exportauditjson?search=export-admin&range=all");
        var json = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("export-admin", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"TimeZone\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SqliteProvider_AppliesMigrations_AndPersistsSharesAndAuditLogs()
    {
        await using var factory = new SqliteTestWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });

        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string sharedUsername = "sqlite.user";
        const string sharedPassword = "SqlitePassword!123";

        var created = await CreateShareAsync(client, recipientEmail, sharedUsername, sharedPassword);
        var accessResponse = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var accessHtml = await accessResponse.Content.ReadAsStringAsync();

        accessResponse.EnsureSuccessStatusCode();
        Assert.Contains("Shared Credentials", accessHtml, StringComparison.OrdinalIgnoreCase);

        var auditHtml = await client.GetStringAsync("/admin/audit");
        Assert.Contains("share.create", auditHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("share.access", auditHtml, StringComparison.OrdinalIgnoreCase);
    }

    private HttpClient CreateClient()
    {
        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = true
        });
    }

    private static async Task LoginAsAdminAsync(HttpClient client)
    {
        var loginPage = await client.GetStringAsync("/account/login");
        var antiForgery = ExtractAntiForgeryToken(loginPage);

        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Username"] = TestAdminAuth.Username,
                ["Password"] = TestAdminAuth.Password
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
    }

    private static async Task<string> LoginLocalUserAndFollowToHtmlAsync(HttpClient client, string username, string password)
    {
        var loginPage = await client.GetStringAsync("/account/login");
        var loginResponse = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiForgeryToken(loginPage),
            ["Username"] = username,
            ["Password"] = password
        }));

        loginResponse.EnsureSuccessStatusCode();
        return await loginResponse.Content.ReadAsStringAsync();
    }

    private static async Task<(string SharePath, string AccessCode)> CreateShareAsync(
        HttpClient client,
        string recipientEmail,
        string sharedUsername,
        string sharedPassword,
        string pathBase = "")
    {
        var createPath = CombineAppPath(pathBase, "/admin/create");
        var createPage = await client.GetStringAsync(createPath);
        var antiForgery = ExtractAntiForgeryToken(createPage);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, createPath)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["RecipientEmail"] = recipientEmail,
                ["SharedUsername"] = sharedUsername,
                ["Password"] = sharedPassword,
                ["ExpiryHours"] = "4"
            })
        };

        createRequest.Headers.Referrer = new Uri($"https://localhost{createPath}");
        var createResponse = await client.SendAsync(createRequest);
        var createHtml = await createResponse.Content.ReadAsStringAsync();

        createResponse.EnsureSuccessStatusCode();
        return (ExtractSharePath(createHtml), ExtractAccessCode(createHtml));
    }

    private static async Task<HttpResponseMessage> AccessShareAsync(HttpClient client, string sharePath, string email, string code)
    {
        var accessPage = await client.GetStringAsync(sharePath);
        var antiForgery = ExtractAntiForgeryToken(accessPage);
        var token = ExtractTokenFromAccessPage(accessPage);

        var request = new HttpRequestMessage(HttpMethod.Post, "/share/access")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["Email"] = email,
                ["Code"] = code,
                ["Token"] = token
            })
        };

        request.Headers.Referrer = new Uri($"https://localhost{sharePath}");
        return await client.SendAsync(request);
    }

    private static string ExtractAntiForgeryToken(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"\\s+type=\"hidden\"\\s+value=\"(?<value>[^\"]+)\"");
        if (!match.Success)
        {
            throw new InvalidOperationException("Anti-forgery token not found in HTML.");
        }

        return WebUtility.HtmlDecode(match.Groups["value"].Value);
    }

    private static string CreateValidClientEncryptedPayload()
    {
        return JsonSerializer.Serialize(new
        {
            version = ClientEncryptedSecretPayload.Version,
            algorithm = ClientEncryptedSecretPayload.AlgorithmName,
            kdf = ClientEncryptedSecretPayload.KdfName,
            iterations = ClientEncryptedSecretPayload.KdfIterations,
            salt = CreateBase64Bytes(16, 1),
            nonce = CreateBase64Bytes(12, 2),
            ciphertext = CreateBase64Bytes(32, 3)
        });
    }

    private static string CreateBase64Bytes(int length, byte value)
    {
        return Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray());
    }

    private static string ExtractSharePath(string html)
    {
        var match = Regex.Match(html, "https?://[^/\"<>]+(?<path>/(?:[^\"<>/]+/)*s/[a-z0-9]+)");
        if (!match.Success)
        {
            throw new InvalidOperationException("Share path not found in created page.");
        }

        return match.Groups["path"].Value;
    }

    private static string ExtractAccessCode(string html)
    {
        var match = Regex.Match(html, "id=\"createdAccessCode\"[^>]*value=\"(?<code>[^\"]+)\"", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            match = Regex.Match(html, "<dd class=\"col-sm-9\"><strong>(?<code>[A-Za-z0-9#-]+)</strong></dd>", RegexOptions.IgnoreCase);
        }

        if (!match.Success)
        {
            throw new InvalidOperationException("Access code not found in created page.");
        }

        return WebUtility.HtmlDecode(match.Groups["code"].Value);
    }

    private static string ExtractTokenFromAccessPage(string html)
    {
        var match = Regex.Match(html, "name=\"Token\"\\s+value=\"(?<token>[^\"]+)\"");
        if (!match.Success)
        {
            throw new InvalidOperationException("Share token not found in access page.");
        }

        return match.Groups["token"].Value;
    }

    private static string ExtractInputById(string html, string id)
    {
        var escapedId = Regex.Escape(id);
        var match = Regex.Match(html, $"<input[^>]*id=\"{escapedId}\"[^>]*>", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            throw new InvalidOperationException($"Input '{id}' not found in HTML.");
        }

        return match.Value;
    }

    private static string ExtractShareIdFromCredentialPage(string html)
    {
        var match = Regex.Match(html, "name=\"ShareId\"[^>]*value=\"(?<id>[^\"]+)\"");
        if (!match.Success)
        {
            throw new InvalidOperationException("ShareId not found in credential page.");
        }

        return match.Groups["id"].Value;
    }

    private static string ExtractTotpManualKey(string html)
    {
        var match = Regex.Match(html, "<label class=\"form-label\">Manual key</label>\\s*<input[^>]*value=\"(?<key>[A-Z2-7=]+)\"", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            throw new InvalidOperationException("TOTP manual key not found in setup page.");
        }

        return WebUtility.HtmlDecode(match.Groups["key"].Value);
    }

    private static string ComputeTotpCode(string secretKey)
    {
        return new Totp(Base32Encoding.ToBytes(secretKey)).ComputeTotp();
    }

    private static string ExtractShareTokenFromPath(string sharePath)
    {
        var index = sharePath.LastIndexOf('/');
        if (index < 0 || index == sharePath.Length - 1)
        {
            throw new InvalidOperationException("Share token not found in share path.");
        }

        return sharePath[(index + 1)..];
    }

    private static string CombineAppPath(string pathBase, string path)
    {
        var normalizedPath = path.StartsWith('/') ? path : "/" + path;

        if (string.IsNullOrWhiteSpace(pathBase) || string.Equals(pathBase, "/", StringComparison.Ordinal))
        {
            return normalizedPath;
        }

        return pathBase.TrimEnd('/') + normalizedPath;
    }

}

public class ApplicationTimeTests
{
    [Fact]
    public void FormatUtcForDisplay_UsesConfiguredTimeZone()
    {
        var service = new ApplicationTime(new TestTimeZoneSettingsProvider("Europe/Stockholm"));

        var formatted = service.FormatUtcForDisplay(new DateTime(2026, 4, 19, 12, 0, 0, DateTimeKind.Utc));

        Assert.Equal("2026-04-19 14:00:00 +02:00", formatted);
    }

    private sealed class TestTimeZoneSettingsProvider : ITimeZoneSettingsProvider
    {
        private readonly TimeZoneInfo _timeZone;

        public TestTimeZoneSettingsProvider(string timeZoneId)
        {
            _timeZone = TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
        }

        public string GetCurrentTimeZoneId()
        {
            return _timeZone.Id;
        }

        public TimeZoneInfo GetCurrentTimeZone()
        {
            return _timeZone;
        }
    }
}

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var overrides = new Dictionary<string, string?>
            {
                ["Storage:Backend"] = "sqlite",
                ["SqliteStorage:ConnectionString"] = "Data Source=testwebfactory;Mode=Memory;Cache=Shared",
                ["SqliteStorage:ApplyMigrationsOnStartup"] = "true",
                ["AdminAuth:Username"] = TestAdminAuth.Username,
                ["AdminAuth:PasswordHash"] = TestAdminAuth.PasswordHash,
                ["Encryption:Passphrase"] = "unit-test-passphrase-1234567890",
                ["Share:CleanupIntervalSeconds"] = "3600"
            };

            config.AddInMemoryCollection(overrides);
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IShareStore>();
            services.RemoveAll<IAuditLogSink>();
            services.RemoveAll<IAuditLogReader>();

            services.AddSingleton<IShareStore, InMemoryShareStore>();
            services.AddSingleton<InMemoryAuditStore>();
            services.AddSingleton<IAuditLogSink>(provider => provider.GetRequiredService<InMemoryAuditStore>());
            services.AddSingleton<IAuditLogReader>(provider => provider.GetRequiredService<InMemoryAuditStore>());
        });
    }
}

internal class ConfiguredApplicationWebApplicationFactory : TestWebApplicationFactory
{
    private readonly IReadOnlyDictionary<string, string?> _overrides;

    public ConfiguredApplicationWebApplicationFactory(IReadOnlyDictionary<string, string?> overrides)
    {
        _overrides = overrides;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(_overrides);
        });
    }
}

internal sealed class RemoteIpWebApplicationFactory : ConfiguredApplicationWebApplicationFactory
{
    private readonly IPAddress _remoteIpAddress;

    public RemoteIpWebApplicationFactory(IReadOnlyDictionary<string, string?> overrides, IPAddress remoteIpAddress)
        : base(overrides)
    {
        _remoteIpAddress = remoteIpAddress;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IStartupFilter>(new RemoteIpStartupFilter(_remoteIpAddress));
        });
    }
}

internal sealed class RemoteIpStartupFilter : IStartupFilter
{
    private readonly IPAddress _remoteIpAddress;

    public RemoteIpStartupFilter(IPAddress remoteIpAddress)
    {
        _remoteIpAddress = remoteIpAddress;
    }

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = _remoteIpAddress;
                await nextMiddleware();
            });

            next(app);
        };
    }
}

internal sealed class SqliteTestWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseDirectory = Path.Combine(Path.GetTempPath(), "sharepassword-tests", Guid.NewGuid().ToString("N"));

    public string DatabasePath => Path.Combine(_databaseDirectory, "sharepassword.sqlite");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var overrides = new Dictionary<string, string?>
            {
                ["Storage:Backend"] = "sqlite",
                ["SqliteStorage:ApplyMigrationsOnStartup"] = "true",
                ["SqliteStorage:ConnectionString"] = $"Data Source={DatabasePath}",
                ["AdminAuth:Username"] = TestAdminAuth.Username,
                ["AdminAuth:PasswordHash"] = TestAdminAuth.PasswordHash,
                ["Encryption:Passphrase"] = "unit-test-passphrase-1234567890",
                ["Share:CleanupIntervalSeconds"] = "3600",
                ["OidcAuth:Enabled"] = "false"
            };

            config.AddInMemoryCollection(overrides);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (disposing && Directory.Exists(_databaseDirectory))
        {
            Directory.Delete(_databaseDirectory, recursive: true);
        }
    }
}

internal sealed class InMemoryShareStore : IShareStore
{
    private readonly ConcurrentDictionary<Guid, PasswordShare> _shares = new();

    public Task<IReadOnlyCollection<PasswordShare>> GetAllSharesAsync(CancellationToken cancellationToken = default)
    {
        var list = _shares.Values
            .Select(Clone)
            .ToList()
            .AsReadOnly();

        return Task.FromResult<IReadOnlyCollection<PasswordShare>>(list);
    }

    public Task<PasswordShare?> GetShareByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        _shares.TryGetValue(id, out var share);
        return Task.FromResult(share is null ? null : Clone(share));
    }

    public Task<PasswordShare?> GetShareByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var share = _shares.Values.FirstOrDefault(x => x.AccessToken == token);
        return Task.FromResult(share is null ? null : Clone(share));
    }

    public Task UpsertShareAsync(PasswordShare share, CancellationToken cancellationToken = default)
    {
        _shares[share.Id] = Clone(share);
        return Task.CompletedTask;
    }

    public Task DeleteShareAsync(Guid id, CancellationToken cancellationToken = default)
    {
        _shares.TryRemove(id, out _);
        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredSharesAsync(DateTime utcNow, CancellationToken cancellationToken = default)
    {
        var expiredIds = _shares.Values
            .Where(x => x.ExpiresAtUtc <= utcNow)
            .Select(x => x.Id)
            .ToList();

        foreach (var id in expiredIds)
        {
            _shares.TryRemove(id, out _);
        }

        return Task.FromResult(expiredIds.Count);
    }

    private static PasswordShare Clone(PasswordShare share)
    {
        return new PasswordShare
        {
            Id = share.Id,
            RecipientEmail = share.RecipientEmail,
            SharedUsername = share.SharedUsername,
            EncryptedPassword = share.EncryptedPassword,
            SecretEncryptionMode = share.SecretEncryptionMode,
            Instructions = share.Instructions,
            AccessCodeHash = share.AccessCodeHash,
            AccessToken = share.AccessToken,
            CreatedAtUtc = share.CreatedAtUtc,
            ExpiresAtUtc = share.ExpiresAtUtc,
            LastAccessedAtUtc = share.LastAccessedAtUtc,
            CreatedBy = share.CreatedBy,
            RequireOidcLogin = share.RequireOidcLogin,
            FailedAccessAttempts = share.FailedAccessAttempts,
            AccessPausedUntilUtc = share.AccessPausedUntilUtc
        };
    }
}

internal sealed class InMemoryAuditStore : IAuditLogSink, IAuditLogReader
{
    private readonly List<AuditLog> _logs = [];
    private readonly object _sync = new();

    public Task AddAuditAsync(AuditLog auditLog, CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            _logs.Add(Clone(auditLog));
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<AuditLog>> GetLatestAsync(int take, CancellationToken cancellationToken = default)
    {
        List<AuditLog> latest;

        lock (_sync)
        {
            latest = _logs
                .OrderByDescending(x => x.TimestampUtc)
                .Take(take)
                .Select(Clone)
                .ToList();
        }

        return Task.FromResult<IReadOnlyCollection<AuditLog>>(latest);
    }

    private static AuditLog Clone(AuditLog audit)
    {
        return new AuditLog
        {
            Id = audit.Id,
            TimestampUtc = audit.TimestampUtc,
            ActorType = audit.ActorType,
            ActorIdentifier = audit.ActorIdentifier,
            Operation = audit.Operation,
            TargetType = audit.TargetType,
            TargetId = audit.TargetId,
            Success = audit.Success,
            IpAddress = audit.IpAddress,
            UserAgent = audit.UserAgent,
            CorrelationId = audit.CorrelationId,
            Details = audit.Details
        };
    }
}
