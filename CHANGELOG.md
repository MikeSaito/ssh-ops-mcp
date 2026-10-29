# Changelog

## 1.4.1

- Correlate audit records per call and measure handler duration with a monotonic clock.
- Record allow-listed failure codes and transport stages without raw errors or secret values.
- Distinguish returned nonzero command exits and unavailable operation status in audit metadata.
- Preserve existing audit outcomes, rotation and behavior when audit writes fail.

## 1.4.0

- Restrict each MCP launch to explicit servers and tools with an optional local policy.
- Validate Windows file and parent ACLs, credential files and existing state permissions without changing them.
- Add local environment diagnostics, explicit connection probes and secret-free client configuration output.
- Find files, search literal text and preview exact edits before hash-checked atomic replacement.
- Connect through one explicitly authorized bastion with independent authentication and host-key verification.
- Preserve selected routes in download worker snapshots and separate routed local state and request IDs.
- Test Debian OpenSSH, Alpine OpenSSH and Dropbear in isolated Docker networks, including a private target.
- Add latency measurements; production calls still use separate connections. Retained-connection experiments are not enabled in production.
- Add `--connection-file` to avoid Node's native `--env-file` argument handling; retain the legacy flag with a Node option separator.

## 1.3.0

- Preserve action results and operation IDs when the final audit write fails.
- Replace PID-directory mutexes with OS-released SQLite transactions and download worker leases.
- Require Node.js 22.13; keep older state, connection settings and request IDs.
- Sort downloads before limiting, add cursor/state filters and tolerate corrupt entries.
- Index safe history metadata with dirty-marker recovery and file-search fallback.
- Add advisory state usage and preview-first, server-bound cleanup plans valid for 15 minutes.
- Preserve deduplication records, active/unknown work, changed files and plaintext exports.
- Split the Python helper into locally assembled modules; no remote package installation.
- Compare JavaScript/Python masking fixtures and read runtime versions from package metadata.
- Test actual Linux SSH/SFTP file writes, permissions, full disk and crashes around replacement.
- Update body-parser, fast-uri and ip-address within existing dependency ranges.

## 1.2.1

- Updated dotenv to 18.0.8 and Zod to 4.6.7; retained MCP SDK 1.32.1 and SSH2 1.17.0.
- Added compatibility tests for profile parsing, tool schemas, required server IDs and default values.
- Retry temporary Windows state-file replacement locks with bounded backoff, without deleting the original file.
- Classify SSH connection, authentication, host-key, execution and SFTP failures without including raw errors.
- Distinguish the current request not being sent from an unknown command outcome; no automatic SSH command retries.
- Preserve operation IDs and connection details on failed launches and unavailable status checks.
- Reject malformed helper responses without suggesting that a running operation stopped.
- Added synthetic disconnect, timeout, missing-exit-status and invalid-response tests.

## 1.2.0

- Multiple server profiles in one MCP using a private servers file and explicit server IDs.
- Server discovery without credentials or network requests.
- Target-specific operations, history, downloads and audits; no mutable active connection.
- Snapshot credentials over worker IPC with a filtered system environment.
- Existing single-server calls, operation IDs and state paths retained.
- Two-server loopback tests for routing, isolation, outages and download recovery.

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
