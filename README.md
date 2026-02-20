# sharepasswordAzure

[![Build](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml/badge.svg)](https://github.com/mictsi/sharepasswordAzure/actions/workflows/build.yml)

Secure password sharing app built with ASP.NET Core (.NET 10).

Latest release: `v0.1.3` (2026-02-20).

## Repository layout

- `sharepasswordAzure/` — web application project
- `sharepasswordAzure.Tests/` — test project
- `.github/workflows/build.yml` — CI workflow
- `CHANGELOG.md` — changelog
- `RELEASE_NOTES.md` — consolidated release notes

## Quick start

```bash
dotnet restore ./sharepasswordAzure.sln
dotnet run --project ./sharepasswordAzure/sharepasswordAzure.csproj
```

For full configuration and usage instructions, see:

- [sharepasswordAzure/README.md](sharepasswordAzure/README.md)
- [sharepasswordAzure/CONFIGURATION.md](sharepasswordAzure/CONFIGURATION.md)

## Flowdiagram
```mermaid
flowchart TD
    S1["1. Admin logs in"] --> S2["2. Admin creates a password share"]
    S2 --> S3["3. App generates a secure link and access code"]
    S3 --> S4["4. Admin sends link and code to recipient"]
    S4 --> S5["5. Recipient opens link"]
    S5 --> S6["6. Recipient enters email and access code"]
    S6 --> S7["7. App verifies details"]
    S7 --> S8["8. App shows username and password"]
    S8 --> S9["9. Recipient clicks: I have retrieved the passwrod. Delete the password"]
    S9 --> S10{"10. Recipient confirms in dialog?"}
    S10 -->|Yes| S11["11. App deletes the password"]
    S10 -->|No| S12["12. Password remains until expiry"]
    S12 --> S13["13. Share expires automatically after set time"]
```