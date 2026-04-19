param(
	[Parameter(Mandatory = $true)]
	[string]$SubscriptionId,

	[Parameter(Mandatory = $true)]
	[string]$ResourceGroupName,

	[Parameter(Mandatory = $true)]
	[string]$Location,

	[Parameter(Mandatory = $true)]
	[string]$AppServicePlanName,

	[Parameter(Mandatory = $true)]
	[string]$WebAppName,

	[string]$SettingsFile = "./sharepasswordAzure/appsettings.Development.json",
	[Alias("DatabaseProvider")]
	[string]$StorageBackend = "sqlite",
	[string]$SqliteConnectionString = "",
	[bool]$SqliteApplyMigrationsOnStartup = $true,
	[string]$SqlServerConnectionString = "",
	[bool]$SqlServerApplyMigrationsOnStartup = $true,
	[string]$PostgresqlConnectionString = "",
	[bool]$PostgresqlApplyMigrationsOnStartup = $true,

	[string]$AzureKeyVaultVaultUri,

	[string]$AzureTableAuditServiceSasUrl,

	[string]$EncryptionPassphrase,

	[string]$ProjectPath = "./sharepasswordAzure/sharepasswordAzure.csproj",
	[string]$Configuration = "Release",
	[string]$OutputDirectory = "./artifacts/deploy/appservice",
	[string]$Sku = "B1",
	[string]$Runtime = "DOTNETCORE:10.0",
	[string]$AppEnvironment = "Production",

	[string]$AzureKeyVaultTenantId = "",
	[string]$AzureKeyVaultClientId = "",
	[string]$AzureKeyVaultClientSecret = "",
	[string]$AzureKeyVaultSecretPrefix = "sharepassword",
	[string]$AzureTableAuditTableName = "auditlogs",
	[string]$AzureTableAuditPartitionKey = "audit",
	[string]$AdminUsername = "admin",
	[string]$AdminPasswordHash = "",

	[bool]$OidcEnabled = $false,
	[string]$OidcAuthority = "",
	[string]$OidcClientId = "",
	[string]$OidcClientSecret = "",
	[string[]]$OidcScopes = @("openid", "profile", "email"),
	[bool]$OidcRequireHttpsMetadata = $true,
	[bool]$OidcLogTokensForTroubleshooting = $false,
	[string]$OidcCallbackPath = "/signin-oidc",
	[string]$OidcSignedOutCallbackPath = "/signout-callback-oidc",
	[string]$OidcGroupClaimType = "groups",
	[string]$OidcAdminRoleName = "Admin",
	[string]$OidcUserRoleName = "User",
	[string[]]$OidcAdminGroups = @(),
	[string[]]$OidcUserGroups = @(),

	[int]$ShareDefaultExpiryHours = 4,
	[int]$ShareCleanupIntervalSeconds = 60,
	[bool]$EnableHttpsRedirection = $false,

	[bool]$ConsoleAuditLoggingEnabled = $false,
	[string]$ConsoleAuditLoggingLevel = "INFO",
	[string]$LoggingDefaultLevel = "Information",
	[string]$LoggingMicrosoftAspNetCoreLevel = "Warning"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Az {
	param(
		[Parameter(Mandatory = $true)]
		[string[]]$Args
	)

	$output = & az @Args
	$code = $LASTEXITCODE
	if ($code -ne 0) {
		throw "Azure CLI failed (exit $code): az $($Args -join ' ')"
	}

	return $output
}

function Invoke-CommandStrict {
	param(
		[Parameter(Mandatory = $true)]
		[string]$FileName,

		[Parameter(Mandatory = $true)]
		[string[]]$Arguments
	)

	& $FileName @Arguments
	$code = $LASTEXITCODE
	if ($code -ne 0) {
		throw "Command failed (exit $code): $FileName $($Arguments -join ' ')"
	}
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
	throw "Azure CLI is not installed. Install it first: https://aka.ms/installazurecliwindows"
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
	throw "dotnet SDK is not installed or not available in PATH."
}

$settingsJson = $null
if (-not [string]::IsNullOrWhiteSpace($SettingsFile) -and (Test-Path $SettingsFile)) {
	$settingsPath = (Resolve-Path $SettingsFile).Path
	Write-Host "Loading settings from '$settingsPath'..." -ForegroundColor Cyan
	$settingsJson = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json

	if (-not $PSBoundParameters.ContainsKey("StorageBackend") -and $settingsJson.Storage.Backend) { $StorageBackend = [string]$settingsJson.Storage.Backend }
	if (-not $PSBoundParameters.ContainsKey("SqliteConnectionString")) { $SqliteConnectionString = [string]$settingsJson.SqliteStorage.ConnectionString }
	if (-not $PSBoundParameters.ContainsKey("SqliteApplyMigrationsOnStartup")) { $SqliteApplyMigrationsOnStartup = [bool]$settingsJson.SqliteStorage.ApplyMigrationsOnStartup }
	if (-not $PSBoundParameters.ContainsKey("SqlServerConnectionString")) { $SqlServerConnectionString = [string]$settingsJson.SqlServerStorage.ConnectionString }
	if (-not $PSBoundParameters.ContainsKey("SqlServerApplyMigrationsOnStartup")) { $SqlServerApplyMigrationsOnStartup = [bool]$settingsJson.SqlServerStorage.ApplyMigrationsOnStartup }
	if (-not $PSBoundParameters.ContainsKey("PostgresqlConnectionString")) { $PostgresqlConnectionString = [string]$settingsJson.PostgresqlStorage.ConnectionString }
	if (-not $PSBoundParameters.ContainsKey("PostgresqlApplyMigrationsOnStartup")) { $PostgresqlApplyMigrationsOnStartup = [bool]$settingsJson.PostgresqlStorage.ApplyMigrationsOnStartup }

	if (-not $PSBoundParameters.ContainsKey("AzureKeyVaultVaultUri")) { $AzureKeyVaultVaultUri = [string]$settingsJson.AzureStorage.KeyVault.VaultUri }
	if (-not $PSBoundParameters.ContainsKey("AzureKeyVaultTenantId")) { $AzureKeyVaultTenantId = [string]$settingsJson.AzureStorage.KeyVault.TenantId }
	if (-not $PSBoundParameters.ContainsKey("AzureKeyVaultClientId")) { $AzureKeyVaultClientId = [string]$settingsJson.AzureStorage.KeyVault.ClientId }
	if (-not $PSBoundParameters.ContainsKey("AzureKeyVaultClientSecret")) { $AzureKeyVaultClientSecret = [string]$settingsJson.AzureStorage.KeyVault.ClientSecret }
	if (-not $PSBoundParameters.ContainsKey("AzureKeyVaultSecretPrefix")) { $AzureKeyVaultSecretPrefix = [string]$settingsJson.AzureStorage.KeyVault.SecretPrefix }

	if (-not $PSBoundParameters.ContainsKey("AzureTableAuditServiceSasUrl")) { $AzureTableAuditServiceSasUrl = [string]$settingsJson.AzureStorage.TableAudit.ServiceSasUrl }
	if (-not $PSBoundParameters.ContainsKey("AzureTableAuditTableName")) { $AzureTableAuditTableName = [string]$settingsJson.AzureStorage.TableAudit.TableName }
	if (-not $PSBoundParameters.ContainsKey("AzureTableAuditPartitionKey")) { $AzureTableAuditPartitionKey = [string]$settingsJson.AzureStorage.TableAudit.PartitionKey }

	if (-not $PSBoundParameters.ContainsKey("AdminUsername")) { $AdminUsername = [string]$settingsJson.AdminAuth.Username }
	if (-not $PSBoundParameters.ContainsKey("AdminPasswordHash")) { $AdminPasswordHash = [string]$settingsJson.AdminAuth.PasswordHash }

	if (-not $PSBoundParameters.ContainsKey("OidcEnabled")) { $OidcEnabled = [bool]$settingsJson.OidcAuth.Enabled }
	if (-not $PSBoundParameters.ContainsKey("OidcAuthority")) { $OidcAuthority = [string]$settingsJson.OidcAuth.Authority }
	if (-not $PSBoundParameters.ContainsKey("OidcClientId")) { $OidcClientId = [string]$settingsJson.OidcAuth.ClientId }
	if (-not $PSBoundParameters.ContainsKey("OidcClientSecret")) { $OidcClientSecret = [string]$settingsJson.OidcAuth.ClientSecret }
	if (-not $PSBoundParameters.ContainsKey("OidcScopes") -and $settingsJson.OidcAuth.Scopes) { $OidcScopes = @($settingsJson.OidcAuth.Scopes | ForEach-Object { [string]$_ }) }
	if (-not $PSBoundParameters.ContainsKey("OidcLogTokensForTroubleshooting")) { $OidcLogTokensForTroubleshooting = [bool]$settingsJson.OidcAuth.LogTokensForTroubleshooting }
	if (-not $PSBoundParameters.ContainsKey("OidcCallbackPath")) { $OidcCallbackPath = [string]$settingsJson.OidcAuth.CallbackPath }
	if (-not $PSBoundParameters.ContainsKey("OidcSignedOutCallbackPath")) { $OidcSignedOutCallbackPath = [string]$settingsJson.OidcAuth.SignedOutCallbackPath }
	if (-not $PSBoundParameters.ContainsKey("OidcRequireHttpsMetadata")) { $OidcRequireHttpsMetadata = [bool]$settingsJson.OidcAuth.RequireHttpsMetadata }
	if (-not $PSBoundParameters.ContainsKey("OidcGroupClaimType")) { $OidcGroupClaimType = [string]$settingsJson.OidcAuth.GroupClaimType }
	if (-not $PSBoundParameters.ContainsKey("OidcAdminRoleName")) { $OidcAdminRoleName = [string]$settingsJson.OidcAuth.AdminRoleName }
	if (-not $PSBoundParameters.ContainsKey("OidcUserRoleName")) { $OidcUserRoleName = [string]$settingsJson.OidcAuth.UserRoleName }
	if (-not $PSBoundParameters.ContainsKey("OidcAdminGroups") -and $settingsJson.OidcAuth.AdminGroups) { $OidcAdminGroups = @($settingsJson.OidcAuth.AdminGroups | ForEach-Object { [string]$_ }) }
	if (-not $PSBoundParameters.ContainsKey("OidcUserGroups") -and $settingsJson.OidcAuth.UserGroups) { $OidcUserGroups = @($settingsJson.OidcAuth.UserGroups | ForEach-Object { [string]$_ }) }

	if (-not $PSBoundParameters.ContainsKey("EncryptionPassphrase")) { $EncryptionPassphrase = [string]$settingsJson.Encryption.Passphrase }
	if (-not $PSBoundParameters.ContainsKey("ShareDefaultExpiryHours")) { $ShareDefaultExpiryHours = [int]$settingsJson.Share.DefaultExpiryHours }
	if (-not $PSBoundParameters.ContainsKey("ShareCleanupIntervalSeconds")) { $ShareCleanupIntervalSeconds = [int]$settingsJson.Share.CleanupIntervalSeconds }
	if (-not $PSBoundParameters.ContainsKey("EnableHttpsRedirection")) { $EnableHttpsRedirection = [bool]$settingsJson.Application.EnableHttpsRedirection }
	if (-not $PSBoundParameters.ContainsKey("ConsoleAuditLoggingEnabled")) { $ConsoleAuditLoggingEnabled = [bool]$settingsJson.ConsoleAuditLogging.Enabled }
	if (-not $PSBoundParameters.ContainsKey("ConsoleAuditLoggingLevel")) { $ConsoleAuditLoggingLevel = [string]$settingsJson.ConsoleAuditLogging.Level }
	if (-not $PSBoundParameters.ContainsKey("LoggingDefaultLevel") -and $settingsJson.Logging.LogLevel.Default) { $LoggingDefaultLevel = [string]$settingsJson.Logging.LogLevel.Default }
	if (-not $PSBoundParameters.ContainsKey("LoggingMicrosoftAspNetCoreLevel") -and $settingsJson.Logging.LogLevel.'Microsoft.AspNetCore') { $LoggingMicrosoftAspNetCoreLevel = [string]$settingsJson.Logging.LogLevel.'Microsoft.AspNetCore' }
}

$normalizedStorageBackend = ($StorageBackend ?? "sqlite").Trim().ToLowerInvariant()

if ($normalizedStorageBackend -in @("sqlite", "sqllite")) {
	if ([string]::IsNullOrWhiteSpace($SqliteConnectionString)) {
		throw "SqliteStorage:ConnectionString is required when Storage:Backend=sqlite."
	}
}
elseif ($normalizedStorageBackend -in @("sqlserver", "mssql")) {
	if ([string]::IsNullOrWhiteSpace($SqlServerConnectionString)) {
		throw "SqlServerStorage:ConnectionString is required when Storage:Backend=sqlserver."
	}
}
elseif ($normalizedStorageBackend -in @("postgresql", "postgres", "npgsql")) {
	if ([string]::IsNullOrWhiteSpace($PostgresqlConnectionString)) {
		throw "PostgresqlStorage:ConnectionString is required when Storage:Backend=postgresql."
	}
}
elseif ($normalizedStorageBackend -eq "azure") {
	if ([string]::IsNullOrWhiteSpace($AzureKeyVaultVaultUri)) {
		throw "AzureStorage:KeyVault:VaultUri is required when Storage:Backend=azure."
	}

	if ([string]::IsNullOrWhiteSpace($AzureTableAuditServiceSasUrl)) {
		throw "AzureStorage:TableAudit:ServiceSasUrl is required when Storage:Backend=azure."
	}
}
else {
	throw "Unsupported StorageBackend '$StorageBackend'. Supported values are sqlite, sqlserver, postgresql, and azure."
}

if ([string]::IsNullOrWhiteSpace($AdminPasswordHash)) {
	throw "AdminPasswordHash is required. Configure AdminAuth:PasswordHash in the settings file or pass -AdminPasswordHash. Generate one with ./scripts/new-admin-password-hash.ps1."
}

if ([string]::IsNullOrWhiteSpace($EncryptionPassphrase)) {
	throw "EncryptionPassphrase is required. Provide -EncryptionPassphrase or set Encryption:Passphrase in the settings file."
}

try {
	Invoke-Az -Args @("account", "show", "--output", "none") | Out-Null
}
catch {
	throw "Azure CLI is not authenticated. Run 'az login' first."
}

Invoke-Az -Args @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$projectFile = (Resolve-Path $ProjectPath).Path
$outputRoot = (Resolve-Path ".").Path
$deployRoot = Join-Path $outputRoot $OutputDirectory
$publishDir = Join-Path $deployRoot "publish"
$zipPath = Join-Path $deployRoot "$WebAppName.zip"

if (Test-Path $deployRoot) {
	Remove-Item -Path $deployRoot -Recurse -Force
}

New-Item -Path $deployRoot -ItemType Directory -Force | Out-Null

Write-Host "Creating/updating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
Invoke-Az -Args @("group", "create", "--name", $ResourceGroupName, "--location", $Location, "--output", "none") | Out-Null

Write-Host "Creating/updating App Service plan '$AppServicePlanName' (SKU: $Sku, Linux)..." -ForegroundColor Cyan
Invoke-Az -Args @(
	"appservice", "plan", "create",
	"--name", $AppServicePlanName,
	"--resource-group", $ResourceGroupName,
	"--location", $Location,
	"--sku", $Sku,
	"--is-linux",
	"--output", "none"
) | Out-Null

$webAppExists = $false
try {
	$existingName = (Invoke-Az -Args @("webapp", "show", "--resource-group", $ResourceGroupName, "--name", $WebAppName, "--query", "name", "--output", "tsv")).Trim()
	$webAppExists = -not [string]::IsNullOrWhiteSpace($existingName)
}
catch {
	$webAppExists = $false
}

if (-not $webAppExists) {
	Write-Host "Creating web app '$WebAppName'..." -ForegroundColor Cyan
	Invoke-Az -Args @(
		"webapp", "create",
		"--resource-group", $ResourceGroupName,
		"--plan", $AppServicePlanName,
		"--name", $WebAppName,
		"--runtime", $Runtime,
		"--https-only", "true",
		"--output", "none"
	) | Out-Null
}
else {
	Write-Host "Web app '$WebAppName' already exists. Reusing existing app." -ForegroundColor Yellow
}

Write-Host "Applying secure web app defaults..." -ForegroundColor Cyan
Invoke-Az -Args @(
	"webapp", "config", "set",
	"--resource-group", $ResourceGroupName,
	"--name", $WebAppName,
	"--always-on", "true",
	"--http20-enabled", "true",
	"--min-tls-version", "1.2",
	"--ftps-state", "Disabled",
	"--output", "none"
) | Out-Null

$oidcEnabledValue = if ($OidcEnabled) { "true" } else { "false" }
$oidcRequireHttpsMetadataValue = if ($OidcRequireHttpsMetadata) { "true" } else { "false" }
$oidcLogTokensValue = if ($OidcLogTokensForTroubleshooting) { "true" } else { "false" }
$httpsRedirectionValue = if ($EnableHttpsRedirection) { "true" } else { "false" }
$consoleAuditEnabledValue = if ($ConsoleAuditLoggingEnabled) { "true" } else { "false" }
$sqliteApplyMigrationsValue = if ($SqliteApplyMigrationsOnStartup) { "true" } else { "false" }
$sqlServerApplyMigrationsValue = if ($SqlServerApplyMigrationsOnStartup) { "true" } else { "false" }
$postgresqlApplyMigrationsValue = if ($PostgresqlApplyMigrationsOnStartup) { "true" } else { "false" }

$settings = @(
	"ASPNETCORE_ENVIRONMENT=$AppEnvironment",
	"Application__EnableHttpsRedirection=$httpsRedirectionValue",
	"Application__Name=sharepasswordAzure",
	"Kestrel__Endpoints__Http__Url=http://+:8080",
	"Storage__Backend=$normalizedStorageBackend",
	"SqliteStorage__ConnectionString=$SqliteConnectionString",
	"SqliteStorage__ApplyMigrationsOnStartup=$sqliteApplyMigrationsValue",
	"SqlServerStorage__ConnectionString=$SqlServerConnectionString",
	"SqlServerStorage__ApplyMigrationsOnStartup=$sqlServerApplyMigrationsValue",
	"PostgresqlStorage__ConnectionString=$PostgresqlConnectionString",
	"PostgresqlStorage__ApplyMigrationsOnStartup=$postgresqlApplyMigrationsValue",
	"AzureStorage__KeyVault__VaultUri=$AzureKeyVaultVaultUri",
	"AzureStorage__KeyVault__TenantId=$AzureKeyVaultTenantId",
	"AzureStorage__KeyVault__ClientId=$AzureKeyVaultClientId",
	"AzureStorage__KeyVault__ClientSecret=$AzureKeyVaultClientSecret",
	"AzureStorage__KeyVault__SecretPrefix=$AzureKeyVaultSecretPrefix",
	"AzureStorage__TableAudit__ServiceSasUrl=$AzureTableAuditServiceSasUrl",
	"AzureStorage__TableAudit__TableName=$AzureTableAuditTableName",
	"AzureStorage__TableAudit__PartitionKey=$AzureTableAuditPartitionKey",
	"AdminAuth__Username=$AdminUsername",
	"AdminAuth__PasswordHash=$AdminPasswordHash",
	"OidcAuth__Enabled=$oidcEnabledValue",
	"OidcAuth__Authority=$OidcAuthority",
	"OidcAuth__ClientId=$OidcClientId",
	"OidcAuth__ClientSecret=$OidcClientSecret",
	"OidcAuth__LogTokensForTroubleshooting=$oidcLogTokensValue",
	"OidcAuth__CallbackPath=$OidcCallbackPath",
	"OidcAuth__SignedOutCallbackPath=$OidcSignedOutCallbackPath",
	"OidcAuth__RequireHttpsMetadata=$oidcRequireHttpsMetadataValue",
	"OidcAuth__GroupClaimType=$OidcGroupClaimType",
	"OidcAuth__AdminRoleName=$OidcAdminRoleName",
	"OidcAuth__UserRoleName=$OidcUserRoleName",
	"Encryption__Passphrase=$EncryptionPassphrase",
	"Share__DefaultExpiryHours=$ShareDefaultExpiryHours",
	"Share__CleanupIntervalSeconds=$ShareCleanupIntervalSeconds",
	"ConsoleAuditLogging__Enabled=$consoleAuditEnabledValue",
	"ConsoleAuditLogging__Level=$ConsoleAuditLoggingLevel",
	"Logging__LogLevel__Default=$LoggingDefaultLevel",
	"Logging__LogLevel__Microsoft__AspNetCore=$LoggingMicrosoftAspNetCoreLevel",
	"AllowedHosts=*"
)

for ($i = 0; $i -lt $OidcScopes.Count; $i++) {
	$settings += "OidcAuth__Scopes__$i=$($OidcScopes[$i])"
}

for ($i = 0; $i -lt $OidcAdminGroups.Count; $i++) {
	$settings += "OidcAuth__AdminGroups__$i=$($OidcAdminGroups[$i])"
}

for ($i = 0; $i -lt $OidcUserGroups.Count; $i++) {
	$settings += "OidcAuth__UserGroups__$i=$($OidcUserGroups[$i])"
}

Write-Host "Configuring App Service application settings..." -ForegroundColor Cyan
$settingsObject = [ordered]@{}
foreach ($setting in $settings) {
	$separatorIndex = $setting.IndexOf('=')
	if ($separatorIndex -lt 0) {
		continue
	}

	$key = $setting.Substring(0, $separatorIndex)
	$value = $setting.Substring($separatorIndex + 1)
	$settingsObject[$key] = $value
}

$settingsFilePath = Join-Path $deployRoot "appsettings.deploy.json"
$settingsObject | ConvertTo-Json -Compress | Set-Content -Path $settingsFilePath -Encoding utf8

Invoke-Az -Args @(
	"webapp", "config", "appsettings", "set",
	"--resource-group", $ResourceGroupName,
	"--name", $WebAppName,
	"--settings", "@$settingsFilePath",
	"--output", "none"
) | Out-Null

Write-Host "Publishing app from '$projectFile' ($Configuration)..." -ForegroundColor Cyan
Invoke-CommandStrict -FileName "dotnet" -Arguments @(
	"publish", $projectFile,
	"-c", $Configuration,
	"-o", $publishDir,
	"--nologo"
)

Write-Host "Packaging deployment artifact..." -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force

Write-Host "Deploying package to App Service..." -ForegroundColor Cyan
Invoke-Az -Args @(
	"webapp", "deploy",
	"--resource-group", $ResourceGroupName,
	"--name", $WebAppName,
	"--src-path", $zipPath,
	"--type", "zip",
	"--output", "none"
) | Out-Null

$defaultHostName = (Invoke-Az -Args @("webapp", "show", "--resource-group", $ResourceGroupName, "--name", $WebAppName, "--query", "defaultHostName", "--output", "tsv")).Trim()
$appUrl = "https://$defaultHostName"
$portalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"

Write-Host "Deployment completed successfully." -ForegroundColor Green
Write-Host "App URL: $appUrl" -ForegroundColor Green
Write-Host "Azure Portal: $portalUrl" -ForegroundColor Green
