# sharepasswordAzure

[![Build](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml/badge.svg)](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml)

Secure password sharing app built with ASP.NET Core (.NET 10).

Latest release: `0.2.6` (2026-02-25).

## Repository layout

- `sharepasswordAzure/` — web application project
- `sharepasswordAzure.Tests/` — test project
- `.github/workflows/build.yml` — CI workflow
- `CHANGELOG.md` — changelog
- `RELEASE_NOTES.md` — consolidated release notes

## Quick start

```bash
dotnet restore ./sharepasswordAzure.sln
dotnet run --project ./sharepasswordAzure/sharepasswordAzure.csproj
```

For full configuration and usage instructions, see:

- [sharepasswordAzure/README.md](sharepasswordAzure/README.md)
- [sharepasswordAzure/CONFIGURATION.md](sharepasswordAzure/CONFIGURATION.md)

## Azure provisioning script

A helper script is available at `scripts/provision-azure.ps1` to create required Azure resources for this app:

- Resource group
- Storage account + audit table
- Table Service SAS URL with permissions `rwdlacu`
- Key Vault for application secret storage
- Key Vault secret permissions for the app principal (existing principal or newly created app registration)
- Direct output of app config values (including SAS URL unless `-NoSecretOutput` is used)

Example:

```powershell
./scripts/provision-azure.ps1 `
    -SubscriptionId "<subscription-id>" `
    -ResourceGroupName "rg-sharepassword-prod" `
    -Location "swedencentral" `
    -NamePrefix "sharepass"
```

The script prints JSON output with created resource names and app environment variable values.

## Azure App Service deployment script

A helper script is available at `scripts/deploy-appservice.ps1` to:

- Create/update resource group
- Create/update Linux App Service plan and Web App
- Configure required app settings (environment variables)
- Publish and deploy the app package

By default, the script reads application settings from `sharepasswordAzure/appsettings.Development.json` (for example Key Vault, Table SAS URL, admin credentials, OIDC, encryption, and share settings). CLI parameters still override file values when provided.

Example:

```powershell
./scripts/deploy-appservice.ps1 `
    -SubscriptionId "<subscription-id>" `
    -ResourceGroupName "rg-sharepassword-prod" `
    -Location "swedencentral" `
    -AppServicePlanName "asp-sharepassword-prod" `
    -WebAppName "app-sharepassword-prod"
```

The script prints the deployed app URL and Azure Portal URL on success.

## 0.2.6 highlights

- Added `Instructions` field for password shares with multiline formatting support and `1000` character limit.
- Updated share retrieval view to show both `Secret text` and `Instructions` preserving formatting.
- Added sharing guidance on the "Password Share Created" page:
    - Send recipient, link, and expiration time by email.
    - Send access code via SMS to recipient mobile phone.
- Hardened user input validation for token, access code, recipient email, and username lengths/formats.

## Flowdiagram

```mermaid
flowchart TD
    S1["1. Admin logs in"] --> S2["2. Admin creates a password share"]
    S2 --> S3["3. App generates a secure link and access code"]
    S3 --> S4["4. Admin sends recipient, link, and expiration by email"]
    S4 --> S4A["5. Admin sends access code by SMS"]
    S4A --> S5["6. Recipient opens link"]
    S5 --> S6["7. Recipient enters email and access code"]
    S6 --> S7["8. App verifies details"]
    S7 --> S8["9. App shows username, secret text, and instructions"]
    S8 --> S9["10. Recipient clicks: I have retrieved the password. Delete the password"]
    S9 --> S10{"11. Recipient confirms in dialog?"}
    S10 -->|Yes| S11["12. App deletes the password"]
    S10 -->|No| S12["13. Password remains until expiry"]
    S12 --> S13["14. Share expires automatically after set time"]
```
