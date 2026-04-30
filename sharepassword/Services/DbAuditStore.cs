using Microsoft.EntityFrameworkCore;
using SharePassword.Data;
using SharePassword.Models;

namespace SharePassword.Services;

public class DbAuditStore : IAuditLogReader, IAuditLogSink
{
    private readonly ISharePasswordDbContextFactory _dbContextFactory;
    private readonly IDatabaseOperationRunner _databaseOperationRunner;

    public DbAuditStore(ISharePasswordDbContextFactory dbContextFactory, IDatabaseOperationRunner databaseOperationRunner)
    {
        _dbContextFactory = dbContextFactory;
        _databaseOperationRunner = databaseOperationRunner;
    }

    public async Task AddAuditAsync(AuditLog auditLog, CancellationToken cancellationToken = default)
    {
        var entity = CloneAudit(auditLog);

        await ExecuteWriteAsync(
            "write audit log entry",
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                dbContext.AuditLogs.Add(entity);
                await dbContext.SaveChangesAsync(innerCancellationToken);
            },
            cancellationToken);

        auditLog.Id = entity.Id;
        auditLog.TimestampUtc = entity.TimestampUtc;
    }

    public async Task<IReadOnlyCollection<AuditLog>> GetLatestAsync(int take, CancellationToken cancellationToken = default)
    {
        if (take <= 0)
        {
            return Array.Empty<AuditLog>();
        }

        return await _databaseOperationRunner.ExecuteAsync(
            "load latest audit log entries",
            DatabaseOperationPurpose.Read,
            async innerCancellationToken =>
            {
                await using var dbContext = await _dbContextFactory.CreateDbContextAsync(innerCancellationToken);

                return await dbContext.AuditLogs
                    .AsNoTracking()
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(take)
                    .ToListAsync(innerCancellationToken);
            },
            cancellationToken);
    }

    private Task ExecuteWriteAsync(string operationName, Func<CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        return _databaseOperationRunner.ExecuteAsync(operationName, DatabaseOperationPurpose.Write, operation, cancellationToken);
    }

    private static AuditLog CloneAudit(AuditLog auditLog)
    {
        return new AuditLog
        {
            TimestampUtc = EnsureUtc(auditLog.TimestampUtc == default ? DateTime.UtcNow : auditLog.TimestampUtc),
            ActorType = auditLog.ActorType ?? string.Empty,
            ActorIdentifier = auditLog.ActorIdentifier ?? string.Empty,
            Operation = auditLog.Operation ?? string.Empty,
            Success = auditLog.Success,
            TargetType = auditLog.TargetType,
            TargetId = auditLog.TargetId,
            IpAddress = auditLog.IpAddress,
            UserAgent = auditLog.UserAgent,
            CorrelationId = auditLog.CorrelationId,
            Details = auditLog.Details
        };
    }

    private static DateTime EnsureUtc(DateTime value)
    {
        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
    }
}