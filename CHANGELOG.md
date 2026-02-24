# Changelog

All notable changes to this project are documented in this file.

## [0.2.3] - 2026-02-24

### Added
- Added support for multiline secret text input with a maximum size of `1000` characters.
- Added live character counting with remaining characters indicator in the share creation form.
- Added over-limit warning state in the share creation form when secret text exceeds `1000` characters.
- Added test coverage for exact round-trip preservation of multiline/special/YAML/JSON secret content.

### Changed
- Updated create form secret field from single-line password input to multiline textarea for preserving formatting.
- Updated credential display to render secret text in a readonly textarea to preserve line breaks and special characters.
- Updated project version metadata in `sharepasswordAzure.csproj` to `0.2.3`.

### Verified
- Solution build succeeds.
- Test suite passes (`10` tests).

## [0.2.2] - 2026-02-23

### Added
- Introduced a modernized global visual theme with improved focus states and accessibility-oriented styling.
- Added route-scoped Admin/Share UI refinements for tables, forms, badges, headings, and pagination.

### Changed
- Moved the application logo to `sharepasswordAzure/wwwroot/images/logo.png` and updated shared layout branding.
- Updated access mode badge wording from `Entra ID Required` to `Entra ID Required + Email + Code`.
- Updated project version metadata in `sharepasswordAzure.csproj` to `0.2.2`.

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.2.1] - 2026-02-23

### Security
- Sanitized user-influenced audit log fields to mitigate log forging (`CR`/`LF` injection) in console logs.

### Changed
- Centralized sanitization in `AuditLogger` and applied it to persisted audit strings and console output fields.

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.2.0] - 2026-02-23

### Added
- Per-share `Require Entra ID login to access` option in share creation flow.
- OIDC-protected share access mode with enforced recipient identity validation.
- Configurable console audit logging (`ConsoleAuditLogging:Enabled` and `ConsoleAuditLogging:Level`).
- Audit logs paging and search in admin UI with default page size `100`.
- Share list access-mode indicator badge (`Entra ID Required` vs `Email + Code`).

### Changed
- OIDC claim mapping and actor identification for clearer audit usernames.
- Dashboard access scoping for non-admin users based on ownership identity.
- Session cookie timeout configured to 60 minutes.
- Provisioning script now grants `Key Vault Secrets Officer` to the app principal.

### Fixed
- Graceful handling for Key Vault RBAC `403` during share creation.
- Recipient mismatch enforcement for OIDC-required share links on both GET and POST access paths.

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.1.4-alpha.1] - 2026-02-20

### Added
- Role-based access model with separate `Admin` and `User` roles.
- Configurable OIDC group-to-role mapping via `OidcAuth:AdminGroups` and `OidcAuth:UserGroups`.

### Changed
- Enforced `AdminOnly` policy to require admin role membership.
- Added `UserOrAdmin` policy for dashboard and share creation workflows.
- Scoped non-admin dashboard listing to shares created by the signed-in user.
- Restricted non-admin share revocation to owned shares only.
- Limited audit log access and navigation visibility to admin role.
- Expanded configuration templates and docs for OIDC role/group mapping settings.

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.1.3] - 2026-02-20

### Security
- Updated vendored `jquery.validate.js` to remediate code scanning alert #5 (`Unsafe jQuery plugin`).

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.1.2] - 2026-02-20

### Added
- End-user explicit delete flow after password retrieval with a dedicated action button.
- Second-step confirmation dialog before deleting a retrieved password.
- Post-delete confirmation page for end users.
- Integration test coverage for delete-after-retrieve behavior.

### Changed
- Consolidated release notes into a single `RELEASE_NOTES.md` file.
- Updated flow diagrams in top-level documentation to include the manual delete flow.

### Verified
- Solution build succeeds.
- Test suite passes (`8` tests).

## [0.1.1] - 2026-02-20

### Changed
- Updated jQuery from `3.7.1` to `4.0.0` in vendored frontend assets.
- Refreshed files in `sharepasswordAzure/wwwroot/lib/jquery/dist`.

### Verified
- Solution build succeeds.
- Test suite passes (`7` tests).

## [0.1.0] - 2026-02-19

### Added
- Initial public release of the `sharepasswordAzure` application.
- ASP.NET Core web app for secure password sharing with expiring links and access codes.
- Azure Key Vault integration for encrypted credential storage.
- Azure Table Storage-based audit logging.
- Automated background cleanup for expired shares.
- Unit and integration test coverage for core workflows.
