using Microsoft.Extensions.Options;
using SharePassword.Options;

namespace SharePassword.Services;

public sealed class PlatformInitializationService : IPlatformInitializationService
{
    private readonly ILocalUserService _localUserService;
    private readonly ISystemConfigurationService _systemConfigurationService;
    private readonly AdminAuthOptions _adminAuthOptions;

    public PlatformInitializationService(
        ILocalUserService localUserService,
        ISystemConfigurationService systemConfigurationService,
        IOptions<AdminAuthOptions> adminAuthOptions)
    {
        _localUserService = localUserService;
        _systemConfigurationService = systemConfigurationService;
        _adminAuthOptions = adminAuthOptions.Value;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _systemConfigurationService.GetConfigurationAsync(cancellationToken);

        if (_localUserService.IsSupported
            && !string.IsNullOrWhiteSpace(_adminAuthOptions.Username)
            && !string.IsNullOrWhiteSpace(_adminAuthOptions.PasswordHash))
        {
            await _localUserService.EnsureBuiltInAdminAsync(_adminAuthOptions.Username, _adminAuthOptions.PasswordHash, cancellationToken);
        }
    }
}