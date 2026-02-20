# Changelog

All notable changes to this project are documented in this file.

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
