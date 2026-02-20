# Release Notes

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
