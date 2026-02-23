# Release Notes

## v0.2.2

UX and branding refresh release of `sharepasswordAzure`.

### Highlights

- Modernized the app interface for a cleaner, more professional and accessible experience.
- Improved Admin and Share screen readability with refined table, form, badge, and pagination styling.
- Moved logo asset to `wwwroot/images/logo.png` and updated navbar branding.
- Updated Access Mode label to `Entra ID Required + Email + Code` for clearer user expectations.
- Synchronized project version metadata to `0.2.2`.

### Notes

- Release date: 2026-02-23
- Tag: `0.2.2`

## v0.2.1

Security maintenance release of `sharepasswordAzure`.

### Highlights

- Hardened audit logging against log forging by sanitizing user-derived values before logging.
- Applied centralized newline sanitization for audit actor, target, correlation, and details fields.
- Preserved audit functionality and log levels while improving safety of console output.

### Notes

- Release date: 2026-02-23
- Tag: `0.2.1`

## v0.2.0

Feature and security release of `sharepasswordAzure`.

### Highlights

- Added per-share option to require Entra ID (OIDC) login before access.
- Enforced recipient-only access for OIDC-protected share links.
- Added role-aware audit improvements for OIDC login attempt/success/failure flows.
- Added audit logs dashboard improvements with default 100 rows, paging, and search.
- Added config-driven console audit logging with levels `DEBUG`, `INFO`, and `ERROR`.
- Improved user ownership scoping so non-admin users only see/revoke shares they created, while admins see all shares.
- Added robust Azure Key Vault permission error handling for share creation.
- Updated Azure provisioning script to assign `Key Vault Secrets Officer` role to app principal.

### Notes

- Release date: 2026-02-23
- Tag: `0.2.0`

## v0.1.4-alpha.1

Alpha feature release of `sharepasswordAzure`.

### Highlights

- Added role-based access controls with separate `Admin` and `User` roles.
- Added configurable OIDC group claim mapping to roles (`AdminGroups`/`UserGroups`).
- Restricted audit log visibility to admin role.
- Updated dashboard behavior so users only see and revoke shares they created.
- Updated configuration files and documentation for new OIDC role/group settings.

### Notes

- Release date: 2026-02-20
- Tag: `v0.1.4-alpha.1`
- Prerelease: `true`

## v0.1.3

Security maintenance release of `sharepasswordAzure`.

### Highlights

- Patched vendored jQuery validation plugin to address code scanning alert #5 (`Unsafe jQuery plugin`).
- Updated `sharepasswordAzure/wwwroot/lib/jquery-validation/dist/jquery.validate.js` with the remediation change.

### Notes

- Release date: 2026-02-20
- Tag: `v0.1.3`

## v0.1.2

Feature release of `sharepasswordAzure`.

### Highlights

- Added end-user "delete after retrieve" flow for shared passwords.
- Added explicit confirmation prompt before password deletion.
- Added deleted-state confirmation page after successful removal.
- Added integration test for end-user deletion flow.
- Consolidated and aligned release documentation and flow diagrams.

### Notes

- Release date: 2026-02-20
- Tag: `v0.1.2`

## v0.1.1

Maintenance release of `sharepasswordAzure`.

### Highlights

- Updated jQuery frontend library from `v3.7.1` to `v4.0.0`.
- Refreshed vendored jQuery distribution assets in `wwwroot/lib/jquery/dist`.
- Verified solution build and test suite after dependency update.

### Notes

- Release date: 2026-02-20
- Tag: `v0.1.1`

## v0.1.0

Initial public release of `sharepasswordAzure`.

### Highlights

- ASP.NET Core web app for secure password sharing with expiring links and access codes.
- Azure Key Vault integration for encrypted credential storage.
- Azure Table Storage-based audit logging.
- Automated background cleanup for expired shares.
- Unit and integration test coverage for core workflows.

### Notes

- Release date: 2026-02-19
- Tag: `v0.1.0`
