namespace SharePassword.Options;

public class AzureTableAuditOptions
{
    public const string SectionName = "AzureTableAudit";

    public string ServiceSasUrl { get; set; } = string.Empty;
    public string TableName { get; set; } = "auditlogs";
    public string PartitionKey { get; set; } = "audit";
}
