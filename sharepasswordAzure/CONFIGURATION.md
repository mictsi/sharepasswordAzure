# Production Configuration Guide

This guide focuses on secure production settings for SharePassword.

## 1) Secrets and credentials

Set strong values before deployment:

- `AdminAuth:Username`: non-default admin name.
- `AdminAuth:Password`: long random password (at least 20 chars).
- `Encryption:Passphrase`: long random secret (at least 32 chars).

Recommendations:

- Do not store production secrets in source-controlled `appsettings*.json`.
- Prefer environment variables or secret stores.
- Rotate `AdminAuth:Password` and `Encryption:Passphrase` regularly.

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

## 3) Database provider and connection strings

Set:

- `Database:Provider`: `sqlite`, `sqlserver`, or `postgresql`
- `ConnectionStrings:DefaultConnection`

### SQLite

Use only for small/single-instance deployments:

```json
"Database": { "Provider": "sqlite" },
"ConnectionStrings": {
  "DefaultConnection": "Data Source=/var/lib/sharepassword/sharepassword.db"
}
```

### SQL Server

Use encrypted transport and managed identity/least privilege where possible:

```json
"Database": { "Provider": "sqlserver" },
"ConnectionStrings": {
  "DefaultConnection": "Server=tcp:sql.example.com,1433;Database=SharePassword;Encrypt=True;TrustServerCertificate=False;User ID=...;Password=..."
}
```

### PostgreSQL

Require SSL mode and least-privilege DB user:

```json
"Database": { "Provider": "postgresql" },
"ConnectionStrings": {
  "DefaultConnection": "Host=db.example.com;Port=5432;Database=sharepassword;Username=sharepassword_app;Password=...;SSL Mode=Require;Trust Server Certificate=false"
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
  "Database": {
    "Provider": "postgresql",
    "AutoCreate": true
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=db.example.com;Port=5432;Database=sharepassword;Username=sharepassword_app;Password=...;SSL Mode=Require;Trust Server Certificate=false"
  },
  "Share": {
    "DefaultExpiryHours": 2,
    "CleanupIntervalSeconds": 30
  }
}
```

Keep secrets out of this file when possible and inject through environment/secret store.
