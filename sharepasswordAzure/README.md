# sharepasswordAzure (.NET 10)

![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet)
[![Build](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml/badge.svg)](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml)

Latest release: `0.2.1` (2026-02-23). See `../RELEASE_NOTES.md`.

Secure password sharing for external users with:

- Local admin login interface
- External user access using unique link + email + access code
- Encrypted password storage in Azure Key Vault
- Audit logging in Azure Storage Table service
- Automatic expiration and cleanup (default 4 hours)
- Audit logging for admin, user, and system operations

## Run

```bash
dotnet restore
dotnet run
```

## Startup scripts (workspace root)

From `e:/KTH/passwordManagerAzureKeyvault`:

- Windows (PowerShell):

```powershell
./start-win.ps1
```

- Linux/macOS (bash):

```bash
chmod +x ./start-linux.sh
./start-linux.sh
```

By default, scripts use URL/port from `sharepasswordAzure/appsettings*.json` (`Kestrel:Endpoints:Http:Url`).

Optional overrides:

- Windows: `./start-win.ps1 -ProjectPath ./sharepasswordAzure/sharepasswordAzure.csproj -Urls http://localhost:5199 -Configuration Release -Environment Development`
- Linux: `./start-linux.sh ./sharepasswordAzure/sharepasswordAzure.csproj http://localhost:5199 Release Development`

## Configuration

Primary settings live in:

- `sharepasswordAzure/appsettings.json`
- `sharepasswordAzure/appsettings.Development.json`

Production hardening guide: `sharepasswordAzure/CONFIGURATION.md`

### Configuration reference

- `Application:Name`: app name shown in config/operations.
- `Application:EnableHttpsRedirection`: set `true` when HTTPS endpoint/certificate is configured.
- `Kestrel:Endpoints:Http:Url`: HTTP host+port (example: `http://0.0.0.0:5099`).
- `AzureKeyVault:VaultUri`: Key Vault URI (example: `https://myvault.vault.azure.net/`).
- `AzureKeyVault:TenantId`: Microsoft Entra tenant ID for app authentication.
- `AzureKeyVault:ClientId`: app registration client ID.
- `AzureKeyVault:ClientSecret`: app registration client secret.
- `AzureKeyVault:SecretPrefix`: secret name prefix used for share records.
- `AzureTableAudit:ServiceSasUrl`: Azure Table service SAS URL.
- `AzureTableAudit:TableName`: table name for audit events.
- `AzureTableAudit:PartitionKey`: partition key used for audit rows.
- `AdminAuth:Username`: local admin username.
- `AdminAuth:Password`: local admin password.
- `OidcAuth:Enabled`: enable OIDC as alternative admin login.
- `OidcAuth:Authority`: OIDC authority/issuer URL.
- `OidcAuth:ClientId`: OIDC client ID.
- `OidcAuth:ClientSecret`: OIDC client secret.
- `OidcAuth:LogTokensForTroubleshooting`: when `true`, writes OIDC tokens to audit logs for troubleshooting.
- `OidcAuth:CallbackPath`: OIDC callback path (default `/signin-oidc`).
- `OidcAuth:SignedOutCallbackPath`: post-logout callback path.
- `OidcAuth:RequireHttpsMetadata`: should be `true` in production.
- `OidcAuth:Scopes`: scopes requested during login.
- `OidcAuth:GroupClaimType`: claim type used for incoming OIDC groups (default `groups`).
- `OidcAuth:AdminRoleName`: app role name used for administrators.
- `OidcAuth:UserRoleName`: app role name used for standard users.
- `OidcAuth:AdminGroups`: OIDC group IDs/names that map to admin role.
- `OidcAuth:UserGroups`: OIDC group IDs/names that map to user role.
- `Encryption:Passphrase`: required secret used for AES encryption at rest.
- `Share:DefaultExpiryHours`: default share expiration in hours.
- `Share:CleanupIntervalSeconds`: frequency for expired-share cleanup service.
- `ConsoleAuditLogging:Enabled`: enable/disable writing audit events to console logs.
- `ConsoleAuditLogging:Level`: console audit level (`DEBUG`, `INFO`, `ERROR`).
- `Logging:LogLevel:*`: standard ASP.NET logging levels.
- `AllowedHosts`: allowed hostnames.

### Using Key Vault

1. Set `AzureKeyVault:*` settings in `sharepasswordAzure/appsettings.Development.json` or environment variables.
2. Grant the app identity permissions to list/get/set/delete secrets in Key Vault.
3. Change `AdminAuth` credentials and `Encryption:Passphrase`.
4. Start app using scripts or `dotnet run`.

Local/test shortcut:

- Configure `AzureKeyVault:*` directly in appsettings or environment variables.

### OIDC login (alternative to local login)

- Enable in config: `OidcAuth:Enabled=true`.
- Fill `OidcAuth:Authority`, `OidcAuth:ClientId`, and `OidcAuth:ClientSecret`.
- Keep `OidcAuth:RequireHttpsMetadata=true` in production.
- When OIDC is enabled, users can sign in via `/account/externallogin`.
- Local admin login remains available only from localhost.
- Group claims are mapped to app roles using `OidcAuth:AdminGroups` and `OidcAuth:UserGroups`.
- If you use `scripts/provision-azure.ps1`, the created OIDC app is configured with `groupMembershipClaims=SecurityGroup` by default so `groups` claims are emitted in tokens.
- Shares can optionally require OIDC login (`Require Entra ID login to access`), in which case only the configured recipient email can access the secret.

### Environment variables (Docker / Azure App Service)

Configuration is read from JSON files and environment variables. Use `__` for nested keys.

Examples:

- `Kestrel__Endpoints__Http__Url=http://localhost:5099`
- `AzureKeyVault__VaultUri=https://passwordmanagerazure.vault.azure.net/`
- `AzureKeyVault__TenantId=<tenant-id>`
- `AzureKeyVault__ClientId=<client-id>`
- `AzureKeyVault__ClientSecret=<client-secret>`
- `AzureKeyVault__SecretPrefix=sharepassword`
- `AzureTableAudit__ServiceSasUrl=<table-service-sas-url>`
- `AzureTableAudit__TableName=auditlogs`
- `AzureTableAudit__PartitionKey=audit`
- `AdminAuth__Username=admin`
- `AdminAuth__Password=<strong-password>`
- `Encryption__Passphrase=<long-random-passphrase>`
- `OidcAuth__Enabled=true`
- `OidcAuth__Authority=https://login.microsoftonline.com/<tenant-id>/v2.0`
- `OidcAuth__ClientId=<client-id>`
- `OidcAuth__ClientSecret=<client-secret>`
- `OidcAuth__LogTokensForTroubleshooting=false`
- `OidcAuth__GroupClaimType=groups`
- `OidcAuth__AdminRoleName=Admin`
- `OidcAuth__UserRoleName=User`
- `ConsoleAuditLogging__Enabled=false`
- `ConsoleAuditLogging__Level=INFO`

For array values (for example scopes), use indexed variables:

- `OidcAuth__Scopes__0=openid`
- `OidcAuth__Scopes__1=profile`
- `OidcAuth__Scopes__2=email`
- `OidcAuth__AdminGroups__0=<entra-group-id-for-admins>`
- `OidcAuth__UserGroups__0=<entra-group-id-for-users>`

## Usage

1. Open `/account/login` and sign in as admin.
2. Create share with recipient email + username + password + expiry.
3. Copy the generated unique link and one-time shown access code to the recipient.
4. Recipient opens the link and submits email + code to view credentials.
5. Share is removed automatically after expiration.

## Audit logs

Audit log entries are stored in Azure Storage Table service (configured by `AzureTableAudit:*`) and are visible in admin UI (`Audit Logs`).

- Login/logout attempts
- Share creation and revoke
- External access attempts (success/failure)
- Automatic cleanup of expired shares
