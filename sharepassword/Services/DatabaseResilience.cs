using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public enum DatabaseOperationPurpose
{
    Read,
    Write,
    Startup,
    HealthCheck
}

public sealed record DatabaseFailureDescriptor(string UserMessage, string DiagnosticMessage, bool IsTransient);

public sealed class DatabaseOperationException : Exception
{
    public DatabaseOperationException(
        string operationName,
        string userMessage,
        string diagnosticMessage,
        bool isTransient,
        Exception? innerException = null)
        : base(diagnosticMessage, innerException)
    {
        OperationName = operationName;
        UserMessage = userMessage;
        DiagnosticMessage = diagnosticMessage;
        IsTransient = isTransient;
    }

    public string OperationName { get; }

    public string UserMessage { get; }

    public string DiagnosticMessage { get; }

    public bool IsTransient { get; }
}

public interface IDatabaseExceptionMapper
{
    bool IsDatabaseException(Exception exception);

    DatabaseFailureDescriptor Describe(Exception exception, DatabaseOperationPurpose purpose, string operationName);
}

public interface IDatabaseOperationRunner
{
    Task ExecuteAsync(string operationName, DatabaseOperationPurpose purpose, Func<CancellationToken, Task> operation, CancellationToken cancellationToken = default);

    Task<T> ExecuteAsync<T>(string operationName, DatabaseOperationPurpose purpose, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default);
}

public sealed class DatabaseExceptionMapper : IDatabaseExceptionMapper
{
    public bool IsDatabaseException(Exception exception)
    {
        return exception is DatabaseOperationException
            || FindInner<TimeoutException>(exception) is not null
            || FindInner<DbException>(exception) is not null
            || FindInner<DbUpdateException>(exception) is not null;
    }

    public DatabaseFailureDescriptor Describe(Exception exception, DatabaseOperationPurpose purpose, string operationName)
    {
        if (exception is DatabaseOperationException databaseOperationException)
        {
            return new DatabaseFailureDescriptor(
                databaseOperationException.UserMessage,
                databaseOperationException.DiagnosticMessage,
                databaseOperationException.IsTransient);
        }

        if (FindInner<TimeoutException>(exception) is TimeoutException timeoutException)
        {
            return new DatabaseFailureDescriptor(
                GetUserMessage(DatabaseFailureKind.Timeout, purpose),
                $"Database operation '{operationName}' timed out: {timeoutException.Message}",
                true);
        }

        if (FindInner<SqliteException>(exception) is SqliteException sqliteException
            && sqliteException.SqliteErrorCode is 5 or 6)
        {
            return new DatabaseFailureDescriptor(
                GetUserMessage(DatabaseFailureKind.Busy, purpose),
                $"Database operation '{operationName}' failed because SQLite is busy: {sqliteException.Message}",
                true);
        }

        if (FindInner<DbException>(exception) is DbException dbException)
        {
            var transient = dbException.IsTransient || dbException is SqliteException { SqliteErrorCode: 5 or 6 };
            var kind = transient ? DatabaseFailureKind.Unavailable : DatabaseFailureKind.Persistence;

            return new DatabaseFailureDescriptor(
                GetUserMessage(kind, purpose),
                $"Database operation '{operationName}' failed: {dbException.Message}",
                transient);
        }

        if (FindInner<DbUpdateException>(exception) is not null)
        {
            return new DatabaseFailureDescriptor(
                GetUserMessage(DatabaseFailureKind.Persistence, purpose),
                $"Database update '{operationName}' failed: {exception.GetBaseException().Message}",
                false);
        }

        return new DatabaseFailureDescriptor(
            GetUserMessage(DatabaseFailureKind.Persistence, purpose),
            $"Database operation '{operationName}' failed: {exception.GetBaseException().Message}",
            false);
    }

    private static TException? FindInner<TException>(Exception exception)
        where TException : Exception
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is TException typed)
            {
                return typed;
            }
        }

        return null;
    }

    private static string GetUserMessage(DatabaseFailureKind kind, DatabaseOperationPurpose purpose)
    {
        return kind switch
        {
            DatabaseFailureKind.Timeout => purpose switch
            {
                DatabaseOperationPurpose.Startup or DatabaseOperationPurpose.HealthCheck => "The application could not connect to the configured database in time.",
                _ => "The database took too long to respond. Please try again in a moment."
            },
            DatabaseFailureKind.Busy => "The database is busy right now. Please try again in a moment.",
            DatabaseFailureKind.Unavailable => purpose switch
            {
                DatabaseOperationPurpose.Startup or DatabaseOperationPurpose.HealthCheck => "The application could not connect to the configured database.",
                _ => "The database is currently unavailable. Please try again in a moment."
            },
            _ => purpose switch
            {
                DatabaseOperationPurpose.Read => "The requested data could not be loaded due to a database error.",
                DatabaseOperationPurpose.Write => "The requested change could not be saved due to a database error.",
                DatabaseOperationPurpose.Startup or DatabaseOperationPurpose.HealthCheck => "The application could not complete its database startup checks.",
                _ => "A database error occurred while processing the request."
            }
        };
    }

    private enum DatabaseFailureKind
    {
        Timeout,
        Busy,
        Unavailable,
        Persistence
    }
}

public sealed class DatabaseOperationRunner : IDatabaseOperationRunner
{
    private readonly DatabaseResilienceOptions _options;
    private readonly IDatabaseExceptionMapper _databaseExceptionMapper;
    private readonly ILogger<DatabaseOperationRunner> _logger;

    public DatabaseOperationRunner(
        IOptions<DatabaseResilienceOptions> options,
        IDatabaseExceptionMapper databaseExceptionMapper,
        ILogger<DatabaseOperationRunner> logger)
    {
        _options = options.Value;
        _databaseExceptionMapper = databaseExceptionMapper;
        _logger = logger;
    }

    public Task ExecuteAsync(string operationName, DatabaseOperationPurpose purpose, Func<CancellationToken, Task> operation, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync<object?>(
            operationName,
            purpose,
            async innerCancellationToken =>
            {
                await operation(innerCancellationToken);
                return null;
            },
            cancellationToken);
    }

    public async Task<T> ExecuteAsync<T>(string operationName, DatabaseOperationPurpose purpose, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default)
    {
        var maxAttempts = Math.Max(1, _options.MaxAttempts);
        var delay = TimeSpan.FromMilliseconds(Math.Max(0, _options.DelayMilliseconds));

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                return await operation(cancellationToken);
            }
            catch (Exception exception) when (_databaseExceptionMapper.IsDatabaseException(exception))
            {
                var failure = _databaseExceptionMapper.Describe(exception, purpose, operationName);
                var shouldRetry = failure.IsTransient && attempt < maxAttempts;

                if (!shouldRetry)
                {
                    throw new DatabaseOperationException(operationName, failure.UserMessage, failure.DiagnosticMessage, failure.IsTransient, exception);
                }

                _logger.LogWarning(
                    exception,
                    "Database operation {OperationName} failed on attempt {Attempt} of {MaxAttempts}. Retrying in {DelayMilliseconds} ms.",
                    operationName,
                    attempt,
                    maxAttempts,
                    delay.TotalMilliseconds);

                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken);
                }
            }
        }

        throw new InvalidOperationException($"Database operation '{operationName}' exhausted all retry attempts without returning or throwing a mapped exception.");
    }
}