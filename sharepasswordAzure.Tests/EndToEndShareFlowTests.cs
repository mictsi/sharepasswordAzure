using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SharePassword.Services;

namespace SharePassword.Tests;

public class EndToEndShareFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public EndToEndShareFlowTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
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
    public async Task ExternalUserWithWrongCode_IsDenied_AndAuditContainsFailureReason()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "external.user", "S3cur3Password!");

        var badAccessResponse = await AccessShareAsync(client, created.SharePath, recipientEmail, "WRONG999");
        var badAccessHtml = await badAccessResponse.Content.ReadAsStringAsync();

        badAccessResponse.EnsureSuccessStatusCode();
        Assert.Contains("Invalid link or access details.", badAccessHtml, StringComparison.OrdinalIgnoreCase);

        var auditHtml = await client.GetStringAsync("/admin/audit");
        Assert.Contains("share.access", auditHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Access code mismatch.", auditHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExternalUserWithWrongEmail_IsDenied_AndAuditContainsEmailMismatch()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var wrongEmail = $"wrong-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "external.user", "S3cur3Password!");

        var response = await AccessShareAsync(client, created.SharePath, wrongEmail, created.AccessCode);
        var html = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Contains("Invalid link or access details.", html, StringComparison.OrdinalIgnoreCase);

        var auditHtml = await client.GetStringAsync("/admin/audit");
        Assert.Contains("Email mismatch.", auditHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExpiredShare_IsDenied_AndRemovedFromDatabase()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "external.user", "S3cur3Password!");

        await ForceExpireShareAsync(recipientEmail);

        var response = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var html = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Contains("This password share has expired.", html, StringComparison.OrdinalIgnoreCase);

        using var scope = _factory.Services.CreateScope();
        var shareStore = scope.ServiceProvider.GetRequiredService<IShareStore>();
        var shareExists = (await shareStore.GetAllSharesAsync()).Any(x => x.RecipientEmail == recipientEmail);
        Assert.False(shareExists);
    }

    [Fact]
    public async Task RevokedShare_CannotBeAccessed()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        var created = await CreateShareAsync(client, recipientEmail, "external.user", "S3cur3Password!");

        await RevokeShareAsync(client, recipientEmail);

        var response = await AccessShareAsync(client, created.SharePath, recipientEmail, created.AccessCode);
        var html = await response.Content.ReadAsStringAsync();

        response.EnsureSuccessStatusCode();
        Assert.Contains("Invalid link or access details.", html, StringComparison.OrdinalIgnoreCase);
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

    [Fact]
    public async Task CreatedShare_IsStoredEncryptedAndCodeHashed()
    {
        using var client = CreateClient();
        await LoginAsAdminAsync(client);

        var recipientEmail = $"recipient-{Guid.NewGuid():N}@example.com";
        const string plainPassword = "S3cur3Password!";
        var created = await CreateShareAsync(client, recipientEmail, "external.user", plainPassword);

        using var scope = _factory.Services.CreateScope();
        var shareStore = scope.ServiceProvider.GetRequiredService<IShareStore>();
        var share = (await shareStore.GetAllSharesAsync())
            .OrderByDescending(x => x.CreatedAtUtc)
            .First(x => x.RecipientEmail == recipientEmail);

        Assert.NotEqual(plainPassword, share.EncryptedPassword);
        Assert.DoesNotContain(plainPassword, share.EncryptedPassword, StringComparison.Ordinal);
        Assert.NotEqual(created.AccessCode, share.AccessCodeHash);
        Assert.NotEqual(created.AccessCode.ToUpperInvariant(), share.AccessCodeHash);
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

    private async Task LoginAsAdminAsync(HttpClient client)
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

    private async Task<(string SharePath, string AccessCode)> CreateShareAsync(
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

    private async Task<HttpResponseMessage> AccessShareAsync(HttpClient client, string sharePath, string email, string code)
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

    private async Task ForceExpireShareAsync(string recipientEmail)
    {
        using var scope = _factory.Services.CreateScope();
        var shareStore = scope.ServiceProvider.GetRequiredService<IShareStore>();

        var share = (await shareStore.GetAllSharesAsync())
            .OrderByDescending(x => x.CreatedAtUtc)
            .First(x => x.RecipientEmail == recipientEmail);

        share.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
        await shareStore.UpsertShareAsync(share);
    }

    private async Task RevokeShareAsync(HttpClient client, string recipientEmail)
    {
        var indexPage = await client.GetStringAsync("/admin/index");
        var antiForgery = ExtractAntiForgeryToken(indexPage);

        using var scope = _factory.Services.CreateScope();
        var shareStore = scope.ServiceProvider.GetRequiredService<IShareStore>();
        var share = (await shareStore.GetAllSharesAsync())
            .OrderByDescending(x => x.CreatedAtUtc)
            .First(x => x.RecipientEmail == recipientEmail);

        var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/admin/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiForgery,
                ["id"] = share.Id.ToString()
            })
        };

        revokeRequest.Headers.Referrer = new Uri("https://localhost/admin/index");
        var revokeResponse = await client.SendAsync(revokeRequest);
        revokeResponse.EnsureSuccessStatusCode();
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
        var match = Regex.Match(html, "name=\"Token\"[^>]*value=\"(?<token>[^\"]+)\"");
        if (!match.Success)
        {
            throw new InvalidOperationException("Share token hidden field not found in access page.");
        }

        return WebUtility.HtmlDecode(match.Groups["token"].Value);
    }
}
