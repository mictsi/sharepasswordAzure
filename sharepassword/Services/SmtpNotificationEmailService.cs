using System.Net;
using System.Net.Mail;
using System.Text;
using SharePassword.Models;

namespace SharePassword.Services;

public sealed class SmtpNotificationEmailService : INotificationEmailService
{
    private readonly ISystemConfigurationService _systemConfigurationService;
    private readonly ILocalUserService _localUserService;
    private readonly IApplicationTime _applicationTime;

    public SmtpNotificationEmailService(
        ISystemConfigurationService systemConfigurationService,
        ILocalUserService localUserService,
        IApplicationTime applicationTime)
    {
        _systemConfigurationService = systemConfigurationService;
        _localUserService = localUserService;
        _applicationTime = applicationTime;
    }

    public async Task NotifyShareAccessedAsync(PasswordShare share, string accessedByIdentifier, CancellationToken cancellationToken = default)
    {
        var configuration = await _systemConfigurationService.GetConfigurationAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(configuration.SmtpHost) || string.IsNullOrWhiteSpace(configuration.SenderEmail))
        {
            return;
        }

        var recipients = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (configuration.NotifyAdminsOnShareAccess)
        {
            foreach (var recipient in ParseRecipients(configuration.AdminNotificationRecipients))
            {
                recipients.Add(recipient);
            }
        }

        if (configuration.NotifyCreatorOnShareAccess)
        {
            var creatorEmail = await _localUserService.ResolveEmailAsync(share.CreatedBy, cancellationToken);
            if (!string.IsNullOrWhiteSpace(creatorEmail))
            {
                recipients.Add(creatorEmail);
            }
        }

        if (recipients.Count == 0)
        {
            return;
        }

        var placeholders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["{{ShareId}}"] = share.Id.ToString(),
            ["{{CreatedBy}}"] = share.CreatedBy,
            ["{{RecipientEmail}}"] = share.RecipientEmail,
            ["{{SharedUsername}}"] = share.SharedUsername,
            ["{{AccessedBy}}"] = accessedByIdentifier,
            ["{{AccessedAt}}"] = share.LastAccessedAtUtc.HasValue ? _applicationTime.FormatUtcForDisplay(share.LastAccessedAtUtc.Value) : string.Empty,
            ["{{ExpiresAt}}"] = _applicationTime.FormatUtcForDisplay(share.ExpiresAtUtc),
            ["{{TimeZoneId}}"] = _applicationTime.TimeZoneId
        };

        var subject = ApplyTemplate(configuration.ShareAccessedSubjectTemplate, placeholders);
        var body = ApplyTemplate(configuration.ShareAccessedBodyTemplate, placeholders);

        using var message = new MailMessage
        {
            From = string.IsNullOrWhiteSpace(configuration.SenderDisplayName)
                ? new MailAddress(configuration.SenderEmail)
                : new MailAddress(configuration.SenderEmail, configuration.SenderDisplayName),
            Subject = subject,
            Body = body,
            BodyEncoding = Encoding.UTF8,
            SubjectEncoding = Encoding.UTF8
        };

        foreach (var recipient in recipients)
        {
            message.To.Add(recipient);
        }

        using var client = new SmtpClient(configuration.SmtpHost, configuration.SmtpPort)
        {
            EnableSsl = configuration.UseTls
        };

        if (!string.IsNullOrWhiteSpace(configuration.SmtpUsername))
        {
            client.Credentials = new NetworkCredential(configuration.SmtpUsername, configuration.SmtpPassword);
        }

        await client.SendMailAsync(message);
    }

    private static IEnumerable<string> ParseRecipients(string? value)
    {
        return (value ?? string.Empty)
            .Split([';', ',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(entry => !string.IsNullOrWhiteSpace(entry))
            .Select(entry => entry.Trim().ToLowerInvariant());
    }

    private static string ApplyTemplate(string? template, IReadOnlyDictionary<string, string> placeholders)
    {
        var resolved = string.IsNullOrWhiteSpace(template) ? string.Empty : template;
        foreach (var placeholder in placeholders)
        {
            resolved = resolved.Replace(placeholder.Key, placeholder.Value ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return resolved;
    }
}