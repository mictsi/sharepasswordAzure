param(
    [string]$Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-PlainText {
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if ([string]::IsNullOrEmpty($Password)) {
    $securePassword = Read-Host -Prompt "Admin password" -AsSecureString
    $Password = ConvertTo-PlainText -SecureString $securePassword
}

if ([string]::IsNullOrWhiteSpace($Password)) {
    throw "Password cannot be empty."
}

$projectPath = Join-Path $PSScriptRoot "..\sharepassword\sharepassword.csproj"
$projectPath = [IO.Path]::GetFullPath($projectPath)

if (-not (Test-Path -LiteralPath $projectPath)) {
    throw "Could not find sharepassword.csproj at $projectPath"
}

$envVarName = "SHAREPASSWORD_HASH_PASSWORD"
$previousValue = [Environment]::GetEnvironmentVariable($envVarName, "Process")

try {
    [Environment]::SetEnvironmentVariable($envVarName, $Password, "Process")
    $hash = dotnet run --project $projectPath --no-launch-profile -- hash-admin-password --password-env-var $envVarName

    if ($LASTEXITCODE -ne 0) {
        throw "Password hash generation failed."
    }

    $hash
}
finally {
    [Environment]::SetEnvironmentVariable($envVarName, $previousValue, "Process")
}
