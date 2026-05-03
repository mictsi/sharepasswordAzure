using Microsoft.EntityFrameworkCore;

namespace SharePassword.Data;

public interface ISharePasswordDbContextFactory
{
    Task<SharePasswordDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default);
}

internal sealed class SharePasswordDbContextFactory<TContext> : ISharePasswordDbContextFactory
    where TContext : SharePasswordDbContext
{
    private readonly DbContextOptions<TContext> _options;

    public SharePasswordDbContextFactory(DbContextOptions<TContext> options)
    {
        _options = options;
    }

    public Task<SharePasswordDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
    {
        var dbContext = Activator.CreateInstance(typeof(TContext), _options)
            ?? throw new InvalidOperationException($"Could not create DbContext '{typeof(TContext).Name}'.");

        return Task.FromResult((SharePasswordDbContext)dbContext);
    }
}
