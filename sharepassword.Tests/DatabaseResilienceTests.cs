using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SharePassword.Models;
using SharePassword.Options;
using SharePassword.Services;

namespace SharePassword.Tests;

public class DatabaseResilienceTests
{
    [Fact]
    public async Task DatabaseOperationRunner_RetriesTransientFailures_UpToConfiguredLimit()
    {
        var runner = CreateRunner(maxAttempts: 3, delayMilliseconds: 0);
        var attempts = 0;

        var result = await runner.ExecuteAsync(
            "transient read",
            DatabaseOperationPurpose.Read,
            _ =>
            {
                attempts++;
                if (attempts < 3)
                {
                    throw new TimeoutException("Temporary database timeout.");
                }

                return Task.FromResult(42);
            });

        Assert.Equal(42, result);
        Assert.Equal(3, attempts);
    }

    [Fact]
    public async Task DatabaseOperationRunner_ThrowsMappedException_AfterFinalAttempt()
    {
        var runner = CreateRunner(maxAttempts: 3, delayMilliseconds: 0);
        var attempts = 0;

        var exception = await Assert.ThrowsAsync<DatabaseOperationException>(() => runner.ExecuteAsync(
            "transient write",
            DatabaseOperationPurpose.Write,
            _ =>
            {
                attempts++;
                throw new TimeoutException("Database timeout.");
            }));

        Assert.Equal(3, attempts);
        Assert.Equal("The database took too long to respond. Please try again in a moment.", exception.UserMessage);
        Assert.True(exception.IsTransient);
    }

    [Fact]
    public async Task AuditLogger_DoesNotThrow_WhenAuditSinkFails()
    {
        var sink = new ThrowingAuditLogSink();
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext.TraceIdentifier = "trace-id";
        httpContextAccessor.HttpContext.Request.Headers.UserAgent = "unit-test-agent";

        var auditLogger = new AuditLogger(
            sink,
            httpContextAccessor,
            new FixedApplicationTime(),
            NullLogger<AuditLogger>.Instance,
            Microsoft.Extensions.Options.Options.Create(new ConsoleAuditLoggingOptions { Enabled = false }));

        await auditLogger.LogAsync("admin", "user@example.com", "share.create", true);

        Assert.Equal(1, sink.CallCount);
    }

    private static DatabaseOperationRunner CreateRunner(int maxAttempts, int delayMilliseconds)
    {
        return new DatabaseOperationRunner(
            Microsoft.Extensions.Options.Options.Create(new DatabaseResilienceOptions
            {
                MaxAttempts = maxAttempts,
                DelayMilliseconds = delayMilliseconds
            }),
            new DatabaseExceptionMapper(),
            NullLogger<DatabaseOperationRunner>.Instance);
    }

    private sealed class ThrowingAuditLogSink : IAuditLogSink
    {
        public int CallCount { get; private set; }

        public Task AddAuditAsync(AuditLog auditLog, CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new InvalidOperationException("Simulated audit store outage.");
        }
    }

    private sealed class FixedApplicationTime : IApplicationTime
    {
        private static readonly DateTimeOffset CurrentTime = new(new DateTime(2025, 1, 1, 12, 0, 0, DateTimeKind.Utc));

        public DateTime UtcNow => CurrentTime.UtcDateTime;

        public DateTimeOffset Now => CurrentTime;

        public TimeZoneInfo TimeZone => TimeZoneInfo.Utc;

        public string TimeZoneId => TimeZoneInfo.Utc.Id;

        public DateTimeOffset ConvertUtcToApplicationTime(DateTime utcDateTime)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(utcDateTime, DateTimeKind.Utc));
        }

        public string FormatUtcForDisplay(DateTime utcDateTime)
        {
            return ConvertUtcToApplicationTime(utcDateTime).ToString("yyyy-MM-dd HH:mm:ss zzz");
        }
    }
}