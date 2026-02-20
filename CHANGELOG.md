# Changelog

All notable changes to this project are documented in this file.

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
