param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [string]$NamePrefix = "sharepass",
    [string]$StorageAccountName = "",
    [string]$KeyVaultName = "",
    [string]$AuditTableName = "auditlogs",
    [string]$SasSecretName = "azure-table-audit-service-sas-url",
    [int]$SasValidityDays = 365,

    # If provided, this principal will be granted KV read access (Secrets User)
    [string]$ExistingPrincipalObjectId = "",

    # Skip app creation; if set and ExistingPrincipalObjectId is empty, no KV reader assignment is created.
    [switch]$SkipAppRegistration,

    # If set, do not include secrets (clientSecret / SAS URL) in console output JSON.
    [switch]$NoSecretOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Az {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    $out = & az @Args
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Azure CLI failed (exit $code): az $($Args -join ' ')"
    }
    return $out
}

function New-RandomSuffix {
    param([int]$Length = 6)
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
}

function ConvertTo-NormalizedPrefix {
    param([string]$InputPrefix)
    $value = $InputPrefix.ToLowerInvariant()
    $value = $value -replace "[^a-z0-9-]", ""
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "sharepass" }
    return $value
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 12,
        [int]$DelaySeconds = 5,
        [string]$OperationName = "operation"
    )

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($i -eq $MaxAttempts) { throw }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Ensure authenticated
try { Invoke-Az -Args @("account","show","--output","none") | Out-Null }
catch { throw "Azure CLI is not authenticated. Run 'az login' first." }

Invoke-Az -Args @("account","set","--subscription",$SubscriptionId) | Out-Null

$prefix = ConvertTo-NormalizedPrefix -InputPrefix $NamePrefix
$suffix = New-RandomSuffix

if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
    $seed = ($prefix -replace "-", "")
    if ($seed.Length -lt 3) { $seed = ($seed + "spa") }
    $StorageAccountName = ($seed + $suffix)
    if ($StorageAccountName.Length -gt 24) { $StorageAccountName = $StorageAccountName.Substring(0, 24) }
}

$StorageAccountName = $StorageAccountName.ToLowerInvariant()
if ($StorageAccountName -notmatch "^[a-z0-9]{3,24}$") {
    throw "StorageAccountName must be 3-24 chars, lowercase letters and numbers only."
}

if ([string]::IsNullOrWhiteSpace($KeyVaultName)) {
    $kvCandidate = "$prefix-kv-$suffix"
    if ($kvCandidate.Length -gt 24) { $kvCandidate = $kvCandidate.Substring(0, 24) }
    $KeyVaultName = $kvCandidate
}

$KeyVaultName = $KeyVaultName.ToLowerInvariant()
if ($KeyVaultName -notmatch "^[a-z0-9-]{3,24}$") {
    throw "KeyVaultName must be 3-24 chars, lowercase letters, numbers, and hyphens only."
}

Write-Host "Creating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
Invoke-Az -Args @("group","create","--name",$ResourceGroupName,"--location",$Location,"--output","none") | Out-Null

Write-Host "Creating storage account '$StorageAccountName'..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "storage","account","create",
    "--name",$StorageAccountName,
    "--resource-group",$ResourceGroupName,
    "--location",$Location,
    "--sku","Standard_LRS",
    "--kind","StorageV2",
    "--https-only","true",
    "--min-tls-version","TLS1_2",
    "--allow-blob-public-access","false",
    "--output","none"
) | Out-Null

$storageKey = (Invoke-Az -Args @(
    "storage","account","keys","list",
    "--resource-group",$ResourceGroupName,
    "--account-name",$StorageAccountName,
    "--query","[0].value",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($storageKey)) { throw "Failed to retrieve storage account key." }

Write-Host "Creating table '$AuditTableName'..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "storage","table","create",
    "--name",$AuditTableName,
    "--account-name",$StorageAccountName,
    "--account-key",$storageKey,
    "--output","none"
) | Out-Null

$expiry = (Get-Date).ToUniversalTime().AddDays($SasValidityDays).ToString("yyyy-MM-ddTHH\:mm\:ssZ")

# NOTE: Account SAS is broad. Keep as-is, but consider a narrower SAS if possible.
$sasToken = (Invoke-Az -Args @(
    "storage","account","generate-sas",
    "--account-name",$StorageAccountName,
    "--account-key",$storageKey,
    "--services","t",
    "--resource-types","sco",
    "--permissions","rwdlacu",
    "--expiry",$expiry,
    "--https-only",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($sasToken)) { throw "Failed to generate SAS token." }

$serviceSasUrl = "https://$StorageAccountName.table.core.windows.net/?$sasToken"

Write-Host "Creating key vault '$KeyVaultName' (RBAC enabled)..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "keyvault","create",
    "--name",$KeyVaultName,
    "--resource-group",$ResourceGroupName,
    "--location",$Location,
    "--enable-rbac-authorization","true",
    "--output","none"
) | Out-Null

$kvId = (Invoke-Az -Args @(
    "keyvault","show",
    "--name",$KeyVaultName,
    "--resource-group",$ResourceGroupName,
    "--query","id",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($kvId)) { throw "Failed to resolve Key Vault resource id." }

# Identify current caller (user or service principal)
$currentObjectId = ""
$currentPrincipalType = ""
try {
    $currentObjectId = (& az ad signed-in-user show --query id --output tsv 2>$null).Trim()
    if (-not [string]::IsNullOrWhiteSpace($currentObjectId)) { $currentPrincipalType = "User" }
} catch { }

if ([string]::IsNullOrWhiteSpace($currentObjectId)) {
    try {
        $currentObjectId = (& az ad signed-in-user show --query id --output tsv 2>$null).Trim()
    } catch { }

    # If not a user session (e.g., az login --service-principal), use the signed-in principal from account
    # This yields the appId; we then look up the SP object id.
    $signedInAppId = (Invoke-Az -Args @("account","show","--query","user.name","--output","tsv")).Trim()
    if ($signedInAppId -match "^[0-9a-fA-F-]{36}$") {
        $currentObjectId = (Invoke-Az -Args @("ad","sp","show","--id",$signedInAppId,"--query","id","--output","tsv")).Trim()
        $currentPrincipalType = "ServicePrincipal"
    }
}

if ([string]::IsNullOrWhiteSpace($currentObjectId)) {
    throw "Could not determine current caller object id. Ensure you are logged in with az and have AAD read access."
}

# RBAC: grant the current caller ability to set secrets on this vault (required for this script)
# Requires the caller to have permission to create role assignments at this scope (Owner or User Access Administrator).
Write-Host "Assigning 'Key Vault Secrets Officer' on vault to current caller ($currentPrincipalType)..." -ForegroundColor Cyan
try {
    Invoke-Az -Args @(
        "role","assignment","create",
        "--assignee-object-id",$currentObjectId,
        "--assignee-principal-type",$currentPrincipalType,
        "--role","Key Vault Secrets Officer",
        "--scope",$kvId,
        "--output","none"
    ) | Out-Null
}
catch {
    throw "Failed to create RBAC role assignment for the current caller. The identity running this script must have 'Owner' or 'User Access Administrator' at the vault/resource-group/subscription scope."
}

# Role assignment propagation can take time; retry secret set
Write-Host "Storing Table Service SAS URL secret '$SasSecretName' in Key Vault..." -ForegroundColor Cyan
Invoke-WithRetry -OperationName "keyvault secret set" -ScriptBlock {
    Invoke-Az -Args @(
        "keyvault","secret","set",
        "--vault-name",$KeyVaultName,
        "--name",$SasSecretName,
        "--value",$serviceSasUrl,
        "--output","none"
    ) | Out-Null
} | Out-Null

$principalObjectId = $ExistingPrincipalObjectId
$appClientId = ""
$appClientSecret = ""
$tenantId = (Invoke-Az -Args @("account","show","--query","tenantId","--output","tsv")).Trim()

if ([string]::IsNullOrWhiteSpace($principalObjectId) -and -not $SkipAppRegistration) {
    $appDisplayName = "$prefix-app-$suffix"

    Write-Host "Creating Microsoft Entra app registration '$appDisplayName'..." -ForegroundColor Cyan
    $appClientId = (Invoke-Az -Args @(
        "ad","app","create",
        "--display-name",$appDisplayName,
        "--sign-in-audience","AzureADMyOrg",
        "--query","appId",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($appClientId)) { throw "Failed to create app registration." }

    Invoke-Az -Args @("ad","sp","create","--id",$appClientId,"--output","none") | Out-Null

    # Poll for SP availability
    $deadline = (Get-Date).AddMinutes(2)
    do {
        try {
            $principalObjectId = (Invoke-Az -Args @("ad","sp","show","--id",$appClientId,"--query","id","--output","tsv")).Trim()
        } catch { $principalObjectId = "" }

        if (-not [string]::IsNullOrWhiteSpace($principalObjectId)) { break }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    if ([string]::IsNullOrWhiteSpace($principalObjectId)) {
        throw "Failed to resolve service principal object id within timeout."
    }

    $appClientSecret = (Invoke-Az -Args @(
        "ad","app","credential","reset",
        "--id",$appClientId,
        "--append",
        "--display-name","sharepasswordAzure",
        "--years","2",
        "--query","password",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($appClientSecret)) { throw "Failed to create client secret for app registration." }
}

# RBAC: grant the app/principal read access to secrets (least privilege)
if (-not [string]::IsNullOrWhiteSpace($principalObjectId)) {
    Write-Host "Assigning 'Key Vault Secrets User' on vault to principal '$principalObjectId'..." -ForegroundColor Cyan
    Invoke-Az -Args @(
        "role","assignment","create",
        "--assignee-object-id",$principalObjectId,
        "--assignee-principal-type","ServicePrincipal",
        "--role","Key Vault Secrets User",
        "--scope",$kvId,
        "--output","none"
    ) | Out-Null
}

$keyVaultUri = "https://$KeyVaultName.vault.azure.net/"

$result = [PSCustomObject]@{
    resourceGroupName = $ResourceGroupName
    location          = $Location
    storageAccountName= $StorageAccountName
    auditTableName    = $AuditTableName
    keyVaultName      = $KeyVaultName
    keyVaultUri       = $keyVaultUri
    keyVaultResourceId= $kvId
    sasSecretName     = $SasSecretName
    servicePrincipalObjectId = $principalObjectId
    tenantId          = $tenantId
    clientId          = $appClientId
    clientSecret      = $(if ($NoSecretOutput) { "" } else { $appClientSecret })
    appEnvironmentVariables = [PSCustomObject]@{
        AzureKeyVault__VaultUri           = $keyVaultUri
        AzureKeyVault__TenantId           = $tenantId
        AzureKeyVault__ClientId           = $appClientId
        AzureKeyVault__ClientSecret       = $(if ($NoSecretOutput) { "" } else { $appClientSecret })
        AzureTableAudit__ServiceSasSecret = $SasSecretName
        AzureTableAudit__TableName        = $AuditTableName
        AzureTableAudit__PartitionKey     = "audit"
    }
    getSasFromKeyVaultCommand = "az keyvault secret show --vault-name $KeyVaultName --name $SasSecretName --query value -o tsv"
}

Write-Host "Provisioning completed." -ForegroundColor Green
$result | ConvertTo-Json -Depth 6