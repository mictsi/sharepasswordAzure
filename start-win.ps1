param(
    [string]$ProjectPath = "./sharepasswordAzure/sharepasswordAzure.csproj",
    [string]$Urls = "",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$Environment = "Development"
)

$ErrorActionPreference = "Stop"

Write-Host "Restoring dependencies..." -ForegroundColor Cyan
dotnet restore

Write-Host "Building project ($Configuration)..." -ForegroundColor Cyan
dotnet build $ProjectPath -c $Configuration

$env:ASPNETCORE_ENVIRONMENT = $Environment
Write-Host "ASPNETCORE_ENVIRONMENT=$Environment" -ForegroundColor DarkGray

if ([string]::IsNullOrWhiteSpace($Urls)) {
    Write-Host "Starting sharepasswordAzure using URL/port from appsettings" -ForegroundColor Green
    Write-Host "Press -Urls to override (example: -Urls https://localhost:7099)" -ForegroundColor DarkGray
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
    dotnet run --project $ProjectPath -c $Configuration --no-launch-profile
    exit $LASTEXITCODE
}

Write-Host "Starting sharepasswordAzure on $Urls" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

dotnet run --project $ProjectPath -c $Configuration --no-launch-profile --urls $Urls
