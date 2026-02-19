using Azure;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;
using System.Text.Json;

namespace SharePassword.Services;

public class KeyVaultStore : IShareStore
{
    private const string ShareKind = "share";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly SecretClient _secretClient;
    private readonly string _prefix;

    public KeyVaultStore(SecretClient secretClient, IOptions<AzureKeyVaultOptions> options)
    {
        _secretClient = secretClient;
        _prefix = string.IsNullOrWhiteSpace(options.Value.SecretPrefix) ? "sharepassword" : options.Value.SecretPrefix.Trim().ToLowerInvariant();
    }

    public async Task<IReadOnlyCollection<PasswordShare>> GetAllSharesAsync(CancellationToken cancellationToken = default)
    {
        var shares = new List<PasswordShare>();

        await foreach (var properties in _secretClient.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            if (properties.Enabled == false || !properties.Name.StartsWith(GetSharePrefix(), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var share = await TryGetShareFromSecretNameAsync(properties.Name, cancellationToken);
            if (share is not null)
            {
                shares.Add(share);
            }
        }

        return shares;
    }

    public async Task<PasswordShare?> GetShareByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await TryGetShareFromSecretNameAsync(GetShareSecretName(id), cancellationToken);
    }

    public async Task<PasswordShare?> GetShareByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        await foreach (var properties in _secretClient.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            if (properties.Enabled == false || !properties.Name.StartsWith(GetSharePrefix(), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!properties.Tags.TryGetValue("token", out var tokenTag) || !string.Equals(tokenTag, token, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return await TryGetShareFromSecretNameAsync(properties.Name, cancellationToken);
        }

        return null;
    }

    public async Task UpsertShareAsync(PasswordShare share, CancellationToken cancellationToken = default)
    {
        var secret = new KeyVaultSecret(GetShareSecretName(share.Id), JsonSerializer.Serialize(share, JsonOptions));
        secret.Properties.ContentType = "application/json";
        secret.Properties.Tags["kind"] = ShareKind;
        secret.Properties.Tags["id"] = share.Id.ToString("N");
        secret.Properties.Tags["token"] = share.AccessToken;
        secret.Properties.Tags["expiresUtc"] = share.ExpiresAtUtc.ToString("O");
        secret.Properties.Tags["recipient"] = share.RecipientEmail;

        await _secretClient.SetSecretAsync(secret, cancellationToken);
    }

    public async Task DeleteShareAsync(Guid id, CancellationToken cancellationToken = default)
    {
        try
        {
            await _secretClient.StartDeleteSecretAsync(GetShareSecretName(id), cancellationToken);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
        }
    }

    public async Task<int> DeleteExpiredSharesAsync(DateTime utcNow, CancellationToken cancellationToken = default)
    {
        var expiredIds = new List<Guid>();

        await foreach (var properties in _secretClient.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            if (properties.Enabled == false || !properties.Name.StartsWith(GetSharePrefix(), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!properties.Tags.TryGetValue("expiresUtc", out var expiresRaw) || !DateTime.TryParse(expiresRaw, out var expiresUtc))
            {
                continue;
            }

            if (expiresUtc <= utcNow && properties.Tags.TryGetValue("id", out var idRaw) && Guid.TryParse(idRaw, out var id))
            {
                expiredIds.Add(id);
            }
        }

        foreach (var id in expiredIds)
        {
            await DeleteShareAsync(id, cancellationToken);
        }

        return expiredIds.Count;
    }

    private async Task<PasswordShare?> TryGetShareFromSecretNameAsync(string secretName, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _secretClient.GetSecretAsync(secretName, cancellationToken: cancellationToken);
            return JsonSerializer.Deserialize<PasswordShare>(response.Value.Value, JsonOptions);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    private string GetSharePrefix() => $"{_prefix}-share-";

    private string GetShareSecretName(Guid id) => $"{GetSharePrefix()}{id:N}";
}
