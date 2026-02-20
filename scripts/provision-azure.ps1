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

# Ensure authenticated
try { Invoke-Az -Args @("account","show","--output","none") | Out-Null }
catch { throw "Azure CLI is not authenticated. Run 'az login' first." }

Invoke-Az -Args @("account","set","--subscription",$SubscriptionId) | Out-Null

$isKeyVaultNameExplicit = -not [string]::IsNullOrWhiteSpace($KeyVaultName)

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
$existingKvResourceGroup = ""
try {
    $existingKvResourceGroup = (Invoke-Az -Args @(
        "keyvault","show",
        "--name",$KeyVaultName,
        "--query","resourceGroup",
        "--output","tsv"
    )).Trim()
} catch {
    $existingKvResourceGroup = ""
}

if (-not [string]::IsNullOrWhiteSpace($existingKvResourceGroup)) {
    if ($existingKvResourceGroup -ieq $ResourceGroupName) {
        Write-Host "Key vault '$KeyVaultName' already exists in resource group '$ResourceGroupName'. Reusing it." -ForegroundColor Yellow
    }
    else {
        if ($isKeyVaultNameExplicit) {
            throw "KeyVaultName '$KeyVaultName' already exists in resource group '$existingKvResourceGroup'. Choose a different -KeyVaultName or omit it to auto-generate a unique name."
        }

        $created = $false
        for ($attempt = 1; $attempt -le 10; $attempt++) {
            $candidateSuffix = New-RandomSuffix
            $candidateName = "$prefix-kv-$candidateSuffix"
            if ($candidateName.Length -gt 24) { $candidateName = $candidateName.Substring(0, 24) }

            $candidateExists = $false
            try {
                $existing = (Invoke-Az -Args @(
                    "keyvault","show",
                    "--name",$candidateName,
                    "--query","name",
                    "--output","tsv"
                )).Trim()
                $candidateExists = -not [string]::IsNullOrWhiteSpace($existing)
            } catch {
                $candidateExists = $false
            }

            if ($candidateExists) { continue }

            $KeyVaultName = $candidateName
            Write-Host "Key vault name already in use globally; using '$KeyVaultName' instead." -ForegroundColor Yellow
            Invoke-Az -Args @(
                "keyvault","create",
                "--name",$KeyVaultName,
                "--resource-group",$ResourceGroupName,
                "--location",$Location,
                "--enable-rbac-authorization","true",
                "--output","none"
            ) | Out-Null
            $created = $true
            break
        }

        if (-not $created) {
            throw "Could not find a unique Key Vault name after multiple attempts. Rerun with an explicit unique -KeyVaultName."
        }
    }
}
else {
    Invoke-Az -Args @(
        "keyvault","create",
        "--name",$KeyVaultName,
        "--resource-group",$ResourceGroupName,
        "--location",$Location,
        "--enable-rbac-authorization","true",
        "--output","none"
    ) | Out-Null
}

$kvId = (Invoke-Az -Args @(
    "keyvault","show",
    "--name",$KeyVaultName,
    "--resource-group",$ResourceGroupName,
    "--query","id",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($kvId)) { throw "Failed to resolve Key Vault resource id." }

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
    azureTableServiceSasUrl = $(if ($NoSecretOutput) { "" } else { $serviceSasUrl })
    servicePrincipalObjectId = $principalObjectId
    tenantId          = $tenantId
    clientId          = $appClientId
    clientSecret      = $(if ($NoSecretOutput) { "" } else { $appClientSecret })
    appEnvironmentVariables = [PSCustomObject]@{
        AzureKeyVault__VaultUri           = $keyVaultUri
        AzureKeyVault__TenantId           = $tenantId
        AzureKeyVault__ClientId           = $appClientId
        AzureKeyVault__ClientSecret       = $(if ($NoSecretOutput) { "" } else { $appClientSecret })
        AzureTableAudit__ServiceSasUrl    = $(if ($NoSecretOutput) { "" } else { $serviceSasUrl })
        AzureTableAudit__TableName        = $AuditTableName
        AzureTableAudit__PartitionKey     = "audit"
    }
}

Write-Host "Provisioning completed." -ForegroundColor Green
Write-Host "App configuration values:" -ForegroundColor Yellow
Write-Host "  AzureKeyVault__VaultUri=$keyVaultUri"
Write-Host "  AzureKeyVault__TenantId=$tenantId"
Write-Host "  AzureKeyVault__ClientId=$appClientId"
Write-Host "  AzureKeyVault__ClientSecret=$(if ($NoSecretOutput) { '<hidden>' } else { $appClientSecret })"
Write-Host "  AzureTableAudit__ServiceSasUrl=$(if ($NoSecretOutput) { '<hidden>' } else { $serviceSasUrl })"
Write-Host "  AzureTableAudit__TableName=$AuditTableName"
Write-Host "  AzureTableAudit__PartitionKey=audit"
$result | ConvertTo-Json -Depth 6