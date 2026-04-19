# Production Configuration Guide

This guide focuses on secure production settings for SharePassword.

## 1) Secrets and credentials

Set strong values before deployment:

- `AdminAuth:Username`: non-default admin name.
- `AdminAuth:PasswordHash`: required PBKDF2-SHA256 admin password hash.
- `Encryption:Passphrase`: long random secret (at least 32 chars).

Recommendations:

- Do not store production secrets in source-controlled `appsettings*.json`.
- Generate `AdminAuth:PasswordHash` with `./scripts/new-admin-password-hash.ps1`.
- The app fails startup if `AdminAuth:PasswordHash` is missing or invalid.
- Prefer environment variables or secret stores.
- Rotate admin credentials and `Encryption:Passphrase` regularly.

## 2) Network and TLS

For production, enable HTTPS redirection and bind HTTPS endpoint:

```json
"Application": {
  "EnableHttpsRedirection": true
}
```

Set Kestrel endpoints behind reverse proxy or directly with TLS certs.

Example HTTP-only (reverse proxy handles TLS):

```json
"Kestrel": {
  "Endpoints": {
    "Http": {
      "Url": "http://0.0.0.0:5099"
    }
  }
}
```

If exposing directly on internet, terminate TLS at app or trusted ingress and restrict inbound ports.

## 3) Storage backend selection

Set:

- `Storage:Backend`: `sqlite`, `sqlserver`, `postgresql`, or `azure`

### SQLite

Use only for small/single-instance deployments:

```json
"Storage": {
  "Backend": "sqlite"
},
"SqliteStorage": {
  "ConnectionString": "Data Source=/var/lib/sharepassword/sharepassword.db",
  "ApplyMigrationsOnStartup": true
}
```

### SQL Server

Use encrypted transport and managed identity/least privilege where possible:

```json
"Storage": {
  "Backend": "sqlserver"
},
"SqlServerStorage": {
  "ConnectionString": "Server=tcp:sql.example.com,1433;Database=SharePassword;Encrypt=True;TrustServerCertificate=False;User ID=...;Password=...",
  "ApplyMigrationsOnStartup": true
}
```

### PostgreSQL

Require SSL mode and least-privilege DB user:

```json
"Storage": {
  "Backend": "postgresql"
},
"PostgresqlStorage": {
  "ConnectionString": "Host=db.example.com;Port=5432;Database=sharepassword;Username=sharepassword_app;Password=...;SSL Mode=Require;Trust Server Certificate=false",
  "ApplyMigrationsOnStartup": true
}
```

### Azure

For the Azure backend, shares are stored in Key Vault and audit logs are stored in Azure Table Storage:

```json
"Storage": {
  "Backend": "azure"
},
"AzureStorage": {
  "KeyVault": {
    "VaultUri": "https://sharepassword.vault.azure.net/",
    "TenantId": "<tenant-id>",
    "ClientId": "<client-id>",
    "ClientSecret": "<client-secret>",
    "SecretPrefix": "sharepassword"
  },
  "TableAudit": {
    "ServiceSasUrl": "https://account.table.core.windows.net/?<sas>",
    "TableName": "auditlogs",
    "PartitionKey": "audit"
  }
}
```

## 4) Share lifetime and cleanup

Security-related retention:

- `Share:DefaultExpiryHours`: keep short (example `1`–`4`).
- `Share:CleanupIntervalSeconds`: low enough to clear expired items quickly (example `30`–`60`).

Example:

```json
"Share": {
  "DefaultExpiryHours": 2,
  "CleanupIntervalSeconds": 30
}
```

## 5) Operational hardening

- Set `AllowedHosts` to known hostnames instead of `*` when possible.
- Run app with least-privileged OS account.
- Restrict database account to only required schema/table permissions.
- Store logs centrally and monitor audit events (`admin.login`, `share.access`, `share.create`, `share.revoke`).
- Back up database securely (encrypted backups).

## 6) Example production override file

Create environment-specific config (for example `appsettings.Production.json`):

```json
{
  "Application": {
    "EnableHttpsRedirection": true
  },
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:5099"
      }
    }
  },
  "Storage": {
    "Backend": "postgresql"
  },
  "PostgresqlStorage": {
    "ConnectionString": "Host=db.example.com;Port=5432;Database=sharepassword;Username=sharepassword_app;Password=...;SSL Mode=Require;Trust Server Certificate=false",
    "ApplyMigrationsOnStartup": true
  },
  "Share": {
    "DefaultExpiryHours": 2,
    "CleanupIntervalSeconds": 30
  }
}
```

Keep secrets out of this file when possible and inject through environment/secret store.
