# sharepassword (.NET 10)

![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet)
[![Build](https://github.com/mictsi/sharepassword/actions/workflows/build.yml/badge.svg)](https://github.com/mictsi/sharepassword/actions/workflows/build.yml)

Latest release: `0.2.6` (2026-02-25). See `../RELEASE_NOTES.md`.

Secure password sharing for external users with:

- Local admin login interface
- External user access using unique link + email + access code
- Selectable storage backend via configuration
- EF Core-backed storage for SQLite, SQL Server, or PostgreSQL
- Azure backend using Key Vault for shares and Azure Table Storage for audit logs
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

By default, scripts use URL/port from `sharepassword/appsettings*.json` (development default: `Kestrel:Endpoints:Https:Url`).

Optional overrides:

- Windows: `./start-win.ps1 -ProjectPath ./sharepassword/sharepassword.csproj -Urls https://localhost:7099 -Configuration Release -Environment Development`
- Linux: `./start-linux.sh ./sharepassword/sharepassword.csproj https://localhost:7099 Release Development`

## Configuration

Primary settings live in:

- `sharepassword/appsettings.json`
- `sharepassword/appsettings.Development.json`

Production hardening guide: `sharepassword/CONFIGURATION.md`

### Configuration reference

- `Application:Name`: app name shown in config/operations.
- `Application:EnableHttpsRedirection`: set `true` when HTTPS endpoint/certificate is configured.
- `Application:PathBase`: base path when the app is published under a sub-URI (default `/`).
- `Application:TimeZoneId`: timezone used for displayed/admin-facing times. Accepts Windows or IANA IDs, default `UTC`.
- `Application:AuthenticationSessionTimeoutMinutes`: idle timeout for the authentication session cookie (default `60`).
- `Application:AuthenticationSlidingExpiration`: when `true`, refreshes the session timeout while the user remains active.
- `Kestrel:Endpoints:Http:Url`: HTTP host+port (example: `http://0.0.0.0:5099`).
- `Storage:Backend`: selected storage backend (`sqlite`, `sqlserver`, `postgresql`, `azure`).
- `SqliteStorage:ConnectionString`: SQLite connection string.
- `SqliteStorage:ApplyMigrationsOnStartup`: applies pending EF Core migrations when `Storage:Backend=sqlite`.
- `SqlServerStorage:ConnectionString`: SQL Server connection string.
- `SqlServerStorage:ApplyMigrationsOnStartup`: applies pending EF Core migrations when `Storage:Backend=sqlserver`.
- `PostgresqlStorage:ConnectionString`: PostgreSQL connection string.
- `PostgresqlStorage:ApplyMigrationsOnStartup`: applies pending EF Core migrations when `Storage:Backend=postgresql`.
- `AzureStorage:KeyVault:*`: Azure Key Vault settings used when `Storage:Backend=azure`.
- `AzureStorage:TableAudit:*`: Azure Table Storage audit settings used when `Storage:Backend=azure`.
- `AdminAuth:Username`: local admin username.
- `AdminAuth:PasswordHash`: required password hash. New hashes use Argon2id and fall back to scrypt if Argon2id is unavailable. Legacy PBKDF2-SHA256 hashes are still accepted.
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

### Generate an admin password hash

The app accepts admin password hashes in these formats:

```text
ARGON2ID$v=19$m=<memory-kib>,t=<iterations>,p=<parallelism>$<salt-base64>$<hash-base64>
SCRYPT$N=<cost>,r=<block-size>,p=<parallelism>$<salt-base64>$<hash-base64>
PBKDF2$SHA256$<iterations>$<salt-base64>$<hash-base64>  (legacy)
```

Generate a new hash from the repository root with the included PowerShell script:

```powershell
./scripts/new-admin-password-hash.ps1
```

The script prompts for the password and prints a value you can paste into `AdminAuth:PasswordHash`. It prefers Argon2id and falls back to scrypt only if Argon2id cannot be used on the current runtime.

If you need to pass the password non-interactively:

```powershell
./scripts/new-admin-password-hash.ps1 -Password "use-a-long-random-password"
```

Update your config to use the generated hash:

```json
"AdminAuth": {
  "Username": "admin",
  "PasswordHash": "ARGON2ID$v=19$m=65536,t=3,p=1$<salt>$<hash>"
}
```

Cleartext `AdminAuth:Password` is no longer supported. The app fails startup if `AdminAuth:PasswordHash` is missing or invalid.

### Using Storage Backends

For SQLite, SQL Server, or PostgreSQL:

1. Set `Storage:Backend` to `sqlite`, `sqlserver`, or `postgresql`.
2. Fill the matching `*Storage` section connection string.
3. Set `ApplyMigrationsOnStartup=true` in that section if you want startup migration execution.

For Azure:

1. Set `Storage:Backend` to `azure`.
2. Fill `AzureStorage:KeyVault` for password-share secrets.
3. Fill `AzureStorage:TableAudit` for audit logs.

In all cases:

1. Change `AdminAuth:Username`, configure `AdminAuth:PasswordHash`, and change `Encryption:Passphrase`.
2. If the app is published below the site root, set `Application:PathBase` to that subpath such as `/sharepassword`.
3. Set `Application:TimeZoneId` if admin-facing times should use a timezone other than `UTC`, for example `Europe/Stockholm` or `W. Europe Standard Time`.
4. Adjust `Application:AuthenticationSessionTimeoutMinutes` and `Application:AuthenticationSlidingExpiration` if the default 60-minute session policy is not what you want.
5. Start the app.

Timezone examples for `Application:TimeZoneId`:

- Stockholm: `Europe/Stockholm` or `W. Europe Standard Time`
- London: `Europe/London` or `GMT Standard Time`
- San Francisco: `America/Los_Angeles` or `Pacific Standard Time`
- Tokyo: `Asia/Tokyo` or `Tokyo Standard Time`

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

- `Kestrel__Endpoints__Https__Url=https://localhost:7099`
- `Application__PathBase=/`
- `Application__TimeZoneId=UTC`
- `Application__AuthenticationSessionTimeoutMinutes=60`
- `Application__AuthenticationSlidingExpiration=true`
- `Storage__Backend=sqlite`
- `SqliteStorage__ConnectionString=Data Source=App_Data/sharepassword.db`
- `SqliteStorage__ApplyMigrationsOnStartup=true`
- `SqlServerStorage__ConnectionString=Server=tcp:sql.example.com,1433;Database=SharePassword;Encrypt=True;TrustServerCertificate=False;User ID=sharepassword_app;Password=<password>`
- `PostgresqlStorage__ConnectionString=Host=db.example.com;Port=5432;Database=sharepassword;Username=sharepassword_app;Password=<password>;SSL Mode=Require;Trust Server Certificate=false`
- `AzureStorage__KeyVault__VaultUri=https://myvault.vault.azure.net/`
- `AzureStorage__TableAudit__ServiceSasUrl=<table-service-sas-url>`
- `AdminAuth__Username=admin`
- `AdminAuth__PasswordHash=<argon2id-or-scrypt-hash>`
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
2. Create share with recipient email + username + secret text + instructions + expiry.
3. Send recipient email, unique link, and expiration time by email.
4. Send the 10-character one-time access code separately via SMS to recipient mobile phone.
5. Recipient opens the link and submits email + code to view credentials, secret text, and instructions.
6. Share is removed automatically after expiration.

Secret text notes:

- Max length is `1000` characters.
- Multiline content is supported.
- Plain text, special characters, YAML, and JSON formatting are preserved end-to-end.

Instructions notes:

- Max length is `1000` characters.
- Multiline content is supported.
- Plain text formatting and line breaks are preserved end-to-end.

Access code notes:

- Access codes are exactly `10` characters long.
- Allowed characters are uppercase letters, lowercase letters, numbers, `#`, and `-`.
- Access codes are case-sensitive.

## Audit logs

Audit log entries are stored in the selected backend and are visible in admin UI (`Audit Logs`).

- Login/logout attempts
- Share creation and revoke
- External access attempts (success/failure)
- Automatic cleanup of expired shares
