# Share password application

[![Build](https://github.com/mictsi/sharepassword/actions/workflows/build.yml/badge.svg)](https://github.com/mictsi/sharepassword/actions/workflows/build.yml)


`sharepassword` helps teams share passwords and other sensitive text without leaving the secret in email, chat, or shared documents. An administrator creates a share with a recipient, secret text, optional instructions, and an expiration time. The app generates a unique access link and a separate one-time access code, so the link and code can be delivered through different channels.

Recipients open the link, confirm their email address, and enter the access code before the secret is shown. Shares can be deleted after retrieval and expire automatically if they are not used. For higher-sensitivity secrets, the creator can protect a share with an extra password that encrypts the secret in the browser before it is sent to the server, so the stored database value is only an encrypted payload.

Secure password sharing app built with ASP.NET Core (.NET 10).

Supported storage backends for both shares and audit logs:

- SQLite
- SQL Server
- PostgreSQL
- Azure Key Vault + Azure Table Storage

## Repository layout

- `sharepassword/` — web application project
- `sharepassword.Tests/` — test project
- `.github/workflows/build.yml` — CI workflow
- `docs/CHANGELOG.md` — changelog
- `docs/RELEASE_NOTES.md` — consolidated release notes
- `docs/flowDiagram.md` — user flow diagram

## Quick start

```bash
dotnet restore ./sharepassword.sln
dotnet run --project ./sharepassword/sharepassword.csproj
```

For full configuration and usage instructions, see:

- [docs/app-overview.md](docs/app-overview.md)
- [docs/flowDiagram.md](docs/flowDiagram.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md)
- [sharepassword/README.md](sharepassword/README.md)
- [sharepassword/CONFIGURATION.md](sharepassword/CONFIGURATION.md)

## Admin password hash

Generate a PBKDF2-SHA256 admin password hash from the repository root with:

```powershell
./scripts/new-admin-password-hash.ps1
```

Paste the output into `AdminAuth:PasswordHash`. Cleartext `AdminAuth:Password` is no longer supported.

The full admin authentication configuration is documented in `sharepassword/README.md`.

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
- Flatten `appsettings.json` into App Service application settings
- Publish and deploy the app package

By default, the script reads `sharepassword/appsettings.json`, flattens every JSON setting into ASP.NET Core environment variable keys, and pushes those values to App Service. The script also sets App Service-specific runtime values such as the environment, port binding, and startup command.

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

## Release documentation

See [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) for release summaries and [docs/CHANGELOG.md](docs/CHANGELOG.md) for the full changelog.

## User flow

See [docs/flowDiagram.md](docs/flowDiagram.md) for the current user flow diagram.
