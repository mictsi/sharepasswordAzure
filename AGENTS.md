# AGENTS.md

Best practices for AI coding agents working in this repository.

## 1) Mission and Scope

- Make the smallest safe change that solves the user request.
- Prefer root-cause fixes over quick patches.
- Keep changes focused; do not refactor unrelated code.
- Do not commit or create branches unless explicitly asked.

## 2) Repository Awareness

## 3) Execution Workflow

1. Read relevant files before editing.
2. Confirm assumptions from code, not guesses.
3. Implement minimal targeted changes.
4. Validate with build/tests/lint checks appropriate to the scope.
5. Summarize exactly what changed and any risks.

## 4) Code Change Guidelines

- Match existing style, naming, and architecture.
- Avoid introducing new dependencies unless necessary.
- Do not add inline comments unless requested.
- Avoid one-letter variable names.
- Preserve public APIs unless a breaking change is explicitly requested.
- Keep scripts and automation idempotent where practical.

## 5) Validation Standards

- Run the narrowest relevant checks first (targeted tests/lint/typecheck), then broader project checks as needed.
- Use repository-native commands and scripts rather than ad-hoc alternatives when available.
- Report failures clearly and avoid fixing unrelated failures unless asked.

## 6) Security and Privacy

- Never print or hardcode secrets, tokens, client secrets, SAS values, or passwords.
- Use configuration files and environment variables consistently with existing patterns.
- Preserve and improve secure defaults (HTTPS, secure cookies, validation, logging hygiene).
- Treat audit logging as sensitive: avoid logging secret/user-provided raw values without sanitization.
- Always apply secure best practises
- Always sanitize user inputs

## 7) Dependencies and Tooling Currency

- Prefer latest stable versions of drivers, packages, modules, SDKs, and CLIs.
- Before introducing or upgrading dependencies, check compatibility with current project/runtime constraints.
- Prefer security/patch upgrades promptly; avoid pinning to outdated versions without a documented reason.
- When upgrades are made, update lock/manifests consistently and validate with tests.

## 8) Deployment and Operations Hygiene

- Use existing scripts under `scripts/` for provisioning/deployment when possible.
- Keep deployment changes idempotent and parameterized.
- Do not make destructive Azure operations without explicit user intent.
- When changing Azure-related behavior, update docs if operational steps change.

## 9) Release Hygiene (History-Informed)

- Keep version metadata aligned across code, release notes, and changelog.
- Ensure release artifacts are reproducible from source and stored in `artifacts/release/<version>/`.
- For GitHub releases, always verify all of the following:
	- tag exists on remote,
	- release object exists,
	- release title/version is correct,
	- artifact is attached,
	- artifact download URL works.
- Do not mark release work complete until release + artifact verification passes.

## 10) Documentation and Change Tracking

- Update documentation when behavior, configuration, deployment, or operational steps change.
- Keep docs concise, task-oriented, and accurate.
- Prefer command examples that work from repository root.
- Always keep these files aligned when shipping changes:
	- `README.md` for user/operator-facing behavior,
	- `RELEASE_NOTES.md` for version-specific highlights,
	- `CHANGELOG.md` for chronological change history.
- If no doc impact exists, explicitly state that in the handoff summary.

## 11) Communication

- Be concise, explicit, and action-oriented.
- State assumptions and verification results.
- Provide next logical steps (e.g., run checks, publish release, update docs) when helpful.

