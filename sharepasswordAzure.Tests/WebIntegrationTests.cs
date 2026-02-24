using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SharePassword.Models;
using SharePassword.Services;

namespace SharePassword.Tests;

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
            HandleCookies = false,
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
                ["Username"] = "admin",
                ["Password"] = "admin123!ChangeMe"
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
    public async Task Get_Health_ReturnsSuccess()
    {
        using var client = CreateClient();

        var response = await client.GetAsync("/health");

        response.EnsureSuccessStatusCode();
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
                ["Username"] = "admin",
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
        Assert.Contains("Invalid username/password.", auditHtml, StringComparison.OrdinalIgnoreCase);
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
                ["Username"] = "admin",
                ["Password"] = "admin123!ChangeMe"
            })
        };

        loginRequest.Headers.Referrer = new Uri("https://localhost/account/login");
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
    }

    private static async Task<(string SharePath, string AccessCode)> CreateShareAsync(
        HttpClient client,
        string recipientEmail,
        string sharedUsername,
        string sharedPassword)
    {
        var createPage = await client.GetStringAsync("/admin/create");
        var antiForgery = ExtractAntiForgeryToken(createPage);

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/admin/create")
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

        createRequest.Headers.Referrer = new Uri("https://localhost/admin/create");
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

    private static string ExtractSharePath(string html)
    {
        var match = Regex.Match(html, "https?://[^\"<>]+(?<path>/s/[a-z0-9]+)");
        if (!match.Success)
        {
            throw new InvalidOperationException("Share path not found in created page.");
        }

        return match.Groups["path"].Value;
    }

    private static string ExtractAccessCode(string html)
    {
        var match = Regex.Match(html, "<dd class=\"col-sm-9\"><strong>(?<code>[A-Z0-9]+)</strong></dd>");
        if (!match.Success)
        {
            throw new InvalidOperationException("Access code not found in created page.");
        }

        return match.Groups["code"].Value;
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

    private static string ExtractShareIdFromCredentialPage(string html)
    {
        var match = Regex.Match(html, "name=\"ShareId\"[^>]*value=\"(?<id>[^\"]+)\"");
        if (!match.Success)
        {
            throw new InvalidOperationException("ShareId not found in credential page.");
        }

        return match.Groups["id"].Value;
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
                ["AzureKeyVault:VaultUri"] = "https://unit-test.vault.azure.net/",
                ["AzureTableAudit:ServiceSasUrl"] = "https://unit-test.table.core.windows.net/?sig=fake",
                ["AdminAuth:Username"] = "admin",
                ["AdminAuth:Password"] = "admin123!ChangeMe",
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
            AccessCodeHash = share.AccessCodeHash,
            AccessToken = share.AccessToken,
            CreatedAtUtc = share.CreatedAtUtc,
            ExpiresAtUtc = share.ExpiresAtUtc,
            LastAccessedAtUtc = share.LastAccessedAtUtc,
            CreatedBy = share.CreatedBy
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
