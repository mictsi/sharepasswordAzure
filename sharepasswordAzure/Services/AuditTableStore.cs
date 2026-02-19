using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;

namespace SharePassword.Services;

public class AuditTableStore : IAuditLogReader, IAuditLogSink
{
    private readonly TableClient _tableClient;
    private readonly string _partitionKey;

    public AuditTableStore(TableServiceClient tableServiceClient, IOptions<AzureTableAuditOptions> options)
    {
        var configured = options.Value;
        if (string.IsNullOrWhiteSpace(configured.TableName))
        {
            throw new InvalidOperationException("AzureTableAudit:TableName must be configured.");
        }

        _partitionKey = string.IsNullOrWhiteSpace(configured.PartitionKey) ? "audit" : configured.PartitionKey.Trim();
        _tableClient = tableServiceClient.GetTableClient(configured.TableName);
        _tableClient.CreateIfNotExists();
    }

    public async Task AddAuditAsync(AuditLog auditLog, CancellationToken cancellationToken = default)
    {
        var timestampUtc = auditLog.TimestampUtc == default ? DateTime.UtcNow : DateTime.SpecifyKind(auditLog.TimestampUtc, DateTimeKind.Utc);
        auditLog.TimestampUtc = timestampUtc;

        var entity = new AuditLogTableEntity
        {
            PartitionKey = _partitionKey,
            RowKey = CreateRowKey(timestampUtc),
            TimestampUtc = new DateTimeOffset(timestampUtc),
            ActorType = auditLog.ActorType,
            ActorIdentifier = auditLog.ActorIdentifier,
            Operation = auditLog.Operation,
            Success = auditLog.Success,
            TargetType = auditLog.TargetType,
            TargetId = auditLog.TargetId,
            IpAddress = auditLog.IpAddress,
            UserAgent = auditLog.UserAgent,
            CorrelationId = auditLog.CorrelationId,
            Details = auditLog.Details
        };

        await _tableClient.AddEntityAsync(entity, cancellationToken);
    }

    public async Task<IReadOnlyCollection<AuditLog>> GetLatestAsync(int take, CancellationToken cancellationToken = default)
    {
        var result = new List<AuditLog>();
        var pageSize = Math.Min(Math.Max(1, take), 1000);

        await foreach (var entity in _tableClient.QueryAsync<AuditLogTableEntity>(
            x => x.PartitionKey == _partitionKey,
            maxPerPage: pageSize,
            cancellationToken: cancellationToken))
        {
            result.Add(new AuditLog
            {
                TimestampUtc = entity.TimestampUtc.UtcDateTime,
                ActorType = entity.ActorType ?? string.Empty,
                ActorIdentifier = entity.ActorIdentifier ?? string.Empty,
                Operation = entity.Operation ?? string.Empty,
                Success = entity.Success,
                TargetType = entity.TargetType,
                TargetId = entity.TargetId,
                IpAddress = entity.IpAddress,
                UserAgent = entity.UserAgent,
                CorrelationId = entity.CorrelationId,
                Details = entity.Details
            });

            if (result.Count >= take)
            {
                break;
            }
        }

        return result;
    }

    private static string CreateRowKey(DateTime timestampUtc)
    {
        var reverseTicks = DateTime.MaxValue.Ticks - timestampUtc.Ticks;
        return $"{reverseTicks:D19}-{Guid.NewGuid():N}";
    }

    public class AuditLogTableEntity : ITableEntity
    {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public DateTimeOffset TimestampUtc { get; set; }
        public string? ActorType { get; set; }
        public string? ActorIdentifier { get; set; }
        public string? Operation { get; set; }
        public bool Success { get; set; }
        public string? TargetType { get; set; }
        public string? TargetId { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public string? CorrelationId { get; set; }
        public string? Details { get; set; }
    }
}
