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

	[string]$SettingsFile = "./sharepassword/appsettings.json",
	[string]$ProjectPath = "./sharepassword/sharepassword.csproj",
	[string]$Configuration = "Release",
	[string]$OutputDirectory = "./artifacts/deploy/appservice",
	[string]$Sku = "B1",
	[string]$Runtime = "DOTNETCORE:10.0",
	[string]$AppEnvironment = "Production",
	[int]$AppServicePort = 8080,
	[string]$StartupCommand = ""
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

function ConvertTo-AppSettingValue {
	param(
		[AllowNull()]
		[object]$Value
	)

	if ($null -eq $Value) {
		return ""
	}

	if ($Value -is [bool]) {
		if ($Value) {
			return "true"
		}

		return "false"
	}

	if ($Value -is [string]) {
		return $Value
	}

	if ($Value -is [ValueType]) {
		return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
	}

	return ($Value | ConvertTo-Json -Compress -Depth 64)
}

function Add-FlattenedJsonSettings {
	param(
		[AllowNull()]
		[object]$Source,

		[string]$Prefix = "",

		[Parameter(Mandatory = $true)]
		[System.Collections.Specialized.OrderedDictionary]$Settings
	)

	if ($null -eq $Source) {
		if (-not [string]::IsNullOrWhiteSpace($Prefix)) {
			$Settings[$Prefix] = ""
		}

		return
	}

	if ($Source -is [pscustomobject]) {
		foreach ($property in $Source.PSObject.Properties) {
			$key = if ([string]::IsNullOrWhiteSpace($Prefix)) { $property.Name } else { "${Prefix}__$($property.Name)" }
			Add-FlattenedJsonSettings -Source $property.Value -Prefix $key -Settings $Settings
		}

		return
	}

	if (($Source -is [System.Collections.IEnumerable]) -and -not ($Source -is [string])) {
		$index = 0
		foreach ($item in $Source) {
			$key = "${Prefix}__$index"
			Add-FlattenedJsonSettings -Source $item -Prefix $key -Settings $Settings
			$index++
		}

		return
	}

	if ([string]::IsNullOrWhiteSpace($Prefix)) {
		throw "The settings file root must be a JSON object."
	}

	$Settings[$Prefix] = ConvertTo-AppSettingValue -Value $Source
}

function Get-ProjectAssemblyName {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ProjectFile
	)

	[xml]$projectXml = Get-Content -Path $ProjectFile -Raw
	foreach ($propertyGroup in @($projectXml.Project.PropertyGroup)) {
		$assemblyNameNode = $propertyGroup.SelectSingleNode("AssemblyName")
		if ($null -eq $assemblyNameNode) {
			continue
		}

		$assemblyName = [string]$assemblyNameNode.InnerText
		if (-not [string]::IsNullOrWhiteSpace($assemblyName)) {
			return $assemblyName
		}
	}

	return [IO.Path]::GetFileNameWithoutExtension($ProjectFile)
}

function Get-AppServiceAppSettings {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ResourceGroupName,

		[Parameter(Mandatory = $true)]
		[string]$WebAppName
	)

	$json = Invoke-Az -Args @(
		"webapp", "config", "appsettings", "list",
		"--resource-group", $ResourceGroupName,
		"--name", $WebAppName,
		"--output", "json"
	)

	$result = @{}
	$items = ($json -join "`n") | ConvertFrom-Json
	if ($null -eq $items) {
		return $result
	}

	foreach ($item in @($items)) {
		if ($null -eq $item) {
			continue
		}

		$result[[string]$item.name] = [string]$item.value
	}

	return $result
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
	throw "Azure CLI is not installed. Install it first: https://aka.ms/installazurecliwindows"
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
	throw "dotnet SDK is not installed or not available in PATH."
}

if ($AppServicePort -le 0) {
	throw "AppServicePort must be greater than 0."
}

if ([string]::IsNullOrWhiteSpace($SettingsFile)) {
	throw "SettingsFile is required."
}

if (-not (Test-Path $SettingsFile)) {
	throw "Settings file '$SettingsFile' was not found."
}

$settingsPath = (Resolve-Path $SettingsFile).Path
Write-Host "Loading and flattening settings from '$settingsPath'..." -ForegroundColor Cyan
$settingsJson = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json
$settingsObject = [ordered]@{}
Add-FlattenedJsonSettings -Source $settingsJson -Settings $settingsObject

try {
	Invoke-Az -Args @("account", "show", "--output", "none") | Out-Null
}
catch {
	throw "Azure CLI is not authenticated. Run 'az login' first."
}

Invoke-Az -Args @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$projectFile = (Resolve-Path $ProjectPath).Path
$assemblyName = Get-ProjectAssemblyName -ProjectFile $projectFile
if ([string]::IsNullOrWhiteSpace($StartupCommand)) {
	$StartupCommand = "dotnet $assemblyName.dll"
}

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
	"--startup-file", $StartupCommand,
	"--output", "none"
) | Out-Null

Write-Host "Configuring App Service application settings..." -ForegroundColor Cyan
$managedSettingExactNames = @(
	"ASPNETCORE_ENVIRONMENT",
	"ASPNETCORE_URLS",
	"WEBSITES_PORT",
	"Kestrel__Endpoints__Http__Url",
	"Logging__LogLevel__Microsoft__AspNetCore"
)
$managedSettingPrefixes = @("Kestrel__Endpoints__")

foreach ($property in $settingsJson.PSObject.Properties) {
	if (($property.Value -is [pscustomobject]) -or (($property.Value -is [System.Collections.IEnumerable]) -and -not ($property.Value -is [string]))) {
		$managedSettingPrefixes += "$($property.Name)__"
	}
	else {
		$managedSettingExactNames += $property.Name
	}
}

foreach ($key in @($settingsObject.Keys)) {
	if ([string]$key -like "Kestrel__Endpoints__*") {
		$settingsObject.Remove($key)
	}
}

$settingsObject["ASPNETCORE_ENVIRONMENT"] = $AppEnvironment
$settingsObject["ASPNETCORE_URLS"] = "http://+:$AppServicePort"
$settingsObject["WEBSITES_PORT"] = [string]$AppServicePort
$settingsObject["Kestrel__Endpoints__Http__Url"] = "http://+:$AppServicePort"

$settingsFilePath = Join-Path $deployRoot "appsettings.deploy.json"
$settingsFileItems = @(
	foreach ($entry in $settingsObject.GetEnumerator()) {
		[ordered]@{
			name = [string]$entry.Key
			value = [string]$entry.Value
			slotSetting = $false
		}
	}
)
$settingsFileItems | ConvertTo-Json -Depth 4 | Set-Content -Path $settingsFilePath -Encoding utf8

$existingSettings = Get-AppServiceAppSettings -ResourceGroupName $ResourceGroupName -WebAppName $WebAppName
$staleManagedSettingNames = @()
foreach ($existingSettingName in $existingSettings.Keys) {
	$isManagedSetting = $managedSettingExactNames -contains $existingSettingName
	foreach ($managedSettingPrefix in $managedSettingPrefixes) {
		if ($existingSettingName.StartsWith($managedSettingPrefix, [StringComparison]::Ordinal)) {
			$isManagedSetting = $true
			break
		}
	}

	if (-not $settingsObject.Contains($existingSettingName) -and $isManagedSetting) {
		$staleManagedSettingNames += $existingSettingName
	}
}

if ($staleManagedSettingNames.Count -gt 0) {
	Write-Host "Removing stale script-managed App Service application settings..." -ForegroundColor Cyan
	Invoke-Az -Args (@(
		"webapp", "config", "appsettings", "delete",
		"--resource-group", $ResourceGroupName,
		"--name", $WebAppName,
		"--setting-names"
	) + $staleManagedSettingNames + @("--output", "none")) | Out-Null
}

Invoke-Az -Args @(
	"webapp", "config", "appsettings", "set",
	"--resource-group", $ResourceGroupName,
	"--name", $WebAppName,
	"--settings", "@$settingsFilePath",
	"--output", "none"
) | Out-Null

Write-Host "Verifying App Service application settings..." -ForegroundColor Cyan
$appliedSettings = Get-AppServiceAppSettings -ResourceGroupName $ResourceGroupName -WebAppName $WebAppName
$settingsVerificationFailures = @()
foreach ($entry in $settingsObject.GetEnumerator()) {
	$key = [string]$entry.Key
	$expectedValue = [string]$entry.Value

	if (-not $appliedSettings.ContainsKey($key)) {
		$settingsVerificationFailures += "$key (missing)"
		continue
	}

	if ([string]$appliedSettings[$key] -ne $expectedValue) {
		$settingsVerificationFailures += "$key (mismatch)"
	}
}

if ($settingsVerificationFailures.Count -gt 0) {
	throw "App Service application settings verification failed. Missing or mismatched settings: $($settingsVerificationFailures -join ', ')"
}

Write-Host "Publishing app from '$projectFile' ($Configuration)..." -ForegroundColor Cyan
Invoke-CommandStrict -FileName "dotnet" -Arguments @(
	"publish", $projectFile,
	"-c", $Configuration,
	"-o", $publishDir,
	"--self-contained", "false",
	"-p:UseAppHost=false",
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
	"--clean", "true",
	"--output", "none"
) | Out-Null

$defaultHostName = (Invoke-Az -Args @("webapp", "show", "--resource-group", $ResourceGroupName, "--name", $WebAppName, "--query", "defaultHostName", "--output", "tsv")).Trim()
$appUrl = "https://$defaultHostName"
$portalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"

Write-Host "Deployment completed successfully." -ForegroundColor Green
Write-Host "App URL: $appUrl" -ForegroundColor Green
Write-Host "Azure Portal: $portalUrl" -ForegroundColor Green
