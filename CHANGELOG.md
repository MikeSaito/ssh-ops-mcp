# Changelog

## 1.1.0

- Unified reports with named phases, UTC timestamps, durations and explained outcomes.
- Sequential steps with a shared deadline; failure/cancellation skips later phases without rollback.
- Readable deployment-lock owners and explicit pre-launch resource-busy errors.
- Metadata-only history search with state/resource/time filters and stable cursor pagination.
- Compatibility with existing single-command request hashes and partial legacy reports.
- Linux integration tests using isolated temporary state without production SSH access.

## 1.0.0

Initial release.

- Password, private-key, encrypted-key and SSH-agent login with explicit user/port.
- Required host-key pinning by default; authentication method isolation and disabled agent forwarding.
- CLI with external env-file loading and secret-safe local configuration checking.
- Per-target local state and non-root-account diagnostics without a dedicated extra account.
- Retained 25-tool interface, durable operations/deploy locks, safe edits, resumable private/encrypted downloads and structure-preserving redaction.
- Clean source distribution, MIT license, English/Russian docs, security policy, contribution/release guides, synthetic integration tests and multi-OS CI.
- Updated the MCP SDK and dependency lockfile; CI checks published dependency advisories.
