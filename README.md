# SSH Ops MCP

A local, stdio-only MCP server for administering Linux hosts over SSH. Recover long-running operations after disconnection, edit files with optimistic concurrency checks, and transfer large files with progress and resume.

[Русская документация](README.ru.md) · [Security model](SECURITY.md) · [Contributing](CONTRIBUTING.md)

> Arbitrary shell access is powerful. Every connected AI client can act with the SSH account's permissions. Prefer a dedicated, restricted deployment account; use root only deliberately. This is not a sandbox or an approval system.

## Features

- Password, private key, encrypted private key, or SSH-agent authentication; any SSH user and port.
- SHA-256 server host-key pinning required by default; SSH-agent forwarding disabled.
- 26 tools: shell execution, persistent operations/reports, deployment locks, file preview/hash/write, SFTP uploads/downloads, network/service/journal diagnostics, and secret-presence checks.
- Durable operation IDs, request deduplication, incremental logs and cancellation. Unknown outcomes are never silently retried.
- Hash-checked atomic writes, optional staged validation, owner/mode preservation and private backups.
- Detached downloads with byte progress, pause/resume, source integrity checks, private storage and optional authenticated encryption.
- Minimal audit records without commands, arguments, file contents or raw errors. Heuristic redaction preserves scalar/JSON/YAML structure.
- Independent server profiles and state per host/port/user. No listening HTTP port or cloud credential service.

## Requirements

Local: Node.js 22 or newer, npm, Windows/macOS/Linux. Remote: Linux, an SSH server, Python 3 with its standard library, and SFTP enabled. Service/journal tools additionally require systemd. File/operation helper code uses Linux facilities and is not supported on Windows SSH servers.

Install from source using the instructions below.

## Quick start

After downloading or cloning this repository, open its directory:

```sh
npm ci
node bin/ssh-ops-mcp.js --help
```

Create a private environment file **outside the repository** using [.env.example](.env.example) or an [authentication example](examples/). Replace the example host, user, credentials and fingerprint. Protect the file: owner-only permissions on Unix, an owner-only ACL on Windows. Private credential files must not be symlinks; Unix key/password/passphrase files must be mode 0600 or stricter.

```dotenv
SSH_HOST=203.0.113.10
SSH_PORT=22
SSH_USERNAME=deploy
SSH_AUTH_METHOD=password
SSH_PASSWORD_FILE=/absolute/private/password.txt
SSH_HOST_FINGERPRINT_SHA256=SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The example IP is reserved for documentation and the fingerprint is a placeholder. Obtain the fingerprint of the server's negotiated host key through a trusted console or administrator. A key scan over an untrusted connection does not establish identity. If the host presents multiple key algorithms, pin the key actually negotiated by the SSH library. A changed key is a hard failure until you independently verify the change.

Validate locally without contacting the server or displaying credentials:

```sh
node bin/ssh-ops-mcp.js --env-file /absolute/private/server.env --check-config
```

Then configure your MCP client to launch the same command without `--check-config`. `npm start -- --env-file /absolute/private/server.env` also works. Without `--env-file`, only `.env` beside this package is read, never a parent project's file. Existing process environment overrides file values; avoid stale `SSH_*` variables when switching profiles. Relative credential paths resolve against the selected env file's directory; `~/` is supported for key paths. Use absolute paths for state directories and client configuration.

## Authentication

| `SSH_AUTH_METHOD` | Required credential setting | Optional setting |
| --- | --- | --- |
| `password` | `SSH_PASSWORD` or `SSH_PASSWORD_FILE` | None |
| `private_key` | `SSH_PRIVATE_KEY_PATH` | `SSH_KEY_PASSPHRASE` **or** `SSH_KEY_PASSPHRASE_FILE` |
| `agent` | `SSH_AGENT_SOCKET` or inherited `SSH_AUTH_SOCK` on Unix | On Windows, defaults to the OpenSSH named pipe |

Only the selected method is attempted: there is no password/key/agent fallback. Password files have one optional trailing newline removed. Use OpenSSH/PEM private keys; `.pub` files are not private keys, and PuTTY `.ppk` files need conversion first. Agent keys must already be loaded into the agent and authorized by the server. Hardware-backed keys may work through a compatible agent; hardware prompts, MFA/keyboard-interactive authentication, SSH certificates, ProxyJump and `~/.ssh/config` are not implemented or claimed as tested.

Common options: `SSH_HOST`, `SSH_USERNAME` and `SSH_AUTH_METHOD` are mandatory; `SSH_PORT` defaults to 22. `SSH_HOST_FINGERPRINT_SHA256` accepts `SHA256:base64` or bare base64. `SSH_ALLOW_UNVERIFIED_HOST=true` is an explicit **unsafe development-only** opt-out; never use it for production. `SSH_COMMAND_TIMEOUT_MS` defaults to 60000 for synchronous commands. The optional `SSH_DIAGNOSTIC_USER` is explained below.

## Codex and other MCP clients

[examples/codex.toml](examples/codex.toml) contains two independent profiles. Replace absolute paths and put the entries in your chosen global or project-scoped Codex configuration. Keep passwords out of TOML and use private env-file paths. The example requests tool approval; client approval policy is separate from remote OS permissions.

```toml
[mcp_servers.ssh_prod]
command = "node"
args = ["/absolute/path/ssh-ops-mcp/bin/ssh-ops-mcp.js", "--env-file", "/absolute/private/prod.env"]
startup_timeout_sec = 20
tool_timeout_sec = 120
default_tools_approval_mode = "prompt"
```

On Windows, use paths such as `C:/tools/ssh-ops-mcp/bin/ssh-ops-mcp.js`. For Unix agent authentication, forward `SSH_AUTH_SOCK` using `env_vars = ["SSH_AUTH_SOCK"]`. Restart/reconnect the client after changing configuration. Global configuration can expose these tools to multiple local chats; project configuration limits where the server is configured, but is not a remote security boundary. See the [official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

Clients using an `mcpServers` JSON configuration can adapt [examples/mcp-client.json](examples/mcp-client.json). This local stdio server is not directly reachable by a cloud-only ChatGPT session: it needs a client/local executor capable of launching local processes. Do not expose it as unauthenticated HTTP.

Each process targets one server profile. Register multiple processes under different names for concurrent production/staging or multiple accounts. Local state lives under `~/.ssh-ops-mcp/state/<target-hash>`; `SSH_MCP_STATE_DIR` overrides the **base**, with the target hash still appended. Remote state is under the SSH account's `~/.local/state/ssh-ops-mcp/`.

## Tools and safe workflows

### Execution and deployment

`ssh_exec`, `ssh_server_info`, `ssh_operation_start`, `ssh_operation_status`, `ssh_operation_report`, `ssh_operation_logs`, `ssh_operation_list`, `ssh_operation_cancel`, `ssh_deploy_lock_status`, `ssh_deploy_unlock`.

Give tasks an optional non-secret `title`. Start with either `command` or `steps`, never both. Up to 20 named steps execute in order, each in its own bash shell: working directory and exported variables do not carry over. One deadline applies to the whole operation. Failure, cancellation or timeout skips later steps without rolling back earlier changes.

```json
{
  "request_id": "demo-deploy-001",
  "title": "Deploy demo",
  "resource": "/srv/demo",
  "timeout_seconds": 600,
  "steps": [
    { "name": "Build", "command": "cd /srv/demo && npm run build" },
    { "name": "Test", "command": "cd /srv/demo && npm test" }
  ]
}
```

`ssh_operation_report` combines phase states, UTC timestamps, queue/execution/elapsed durations, exit codes and a readable outcome. Commands and log contents are not included. Legacy reports can have partial timing (`legacy_metadata: true`); missing durations stay null. A successful exit is not a health-check guarantee. Titles, phase names and request IDs are retained metadata and must not contain secrets. Changing only a task title does not change its execution specification or relaunch a reused request ID.

`ssh_deploy_lock_status` includes the owner's title, request/operation ID, current phase, elapsed time, blocking reason and recovery advice. Rejected launches return `resource_busy`, `outcome: not_started` and the blocker: this is not an uncertain launch. Lost runners remain blocked until their effects are verified.

`ssh_operation_list` supports a case-insensitive literal `query` over title/request ID/operation ID/resource, `states`, exact `resource`, timezone-aware ISO `created_after` / `created_before`, and `limit` (1-100). Pass `next_cursor` as `cursor` with the same filters for the next page. Results sort by creation time then ID, newest first. Status filters reflect live state between pages. Commands/log contents are never searched. History scans metadata rather than maintaining a search index; corrupt or unavailable entries are counted in `unavailable_count` and not deleted.

For deployment, backup or migration, call `ssh_operation_start` with a stable `request_id`, `command`, `timeout_seconds`, and shared `resource` (for example `/srv/my-app`). Save the returned `operation_id` and poll status/logs. Reuse the same ID and exact options after an uncertain launch; do not invent another ID. Request reuse prevents duplicate launches, **not** rollback or exactly-once effects across server failure. Different chats must use the same resource identifier and SSH account to coordinate. No resource means the account-wide `__server_admin__` lock. This does not coordinate different OS users or bypassing shell commands.

An SSH/MCP disconnect does not terminate durable work. Timeout/cancel terminates its process group, without reverting completed changes; deliberately detached child processes can escape that group. Lost-process states keep deployment resources blocked until an operator verifies effects and explicitly unlocks. `ssh_exec` is synchronous: connection loss/timeout leaves its outcome unknown and does not guarantee remote termination. It bypasses deployment locks. Never automatically retry an unknown modifying command.

### Files

`ssh_file_hash`, `ssh_read_file`, `ssh_file_preview`, `ssh_write_file`, `ssh_upload_file`, `ssh_secret_presence`.

Hash first, preview the redacted diff, then write with `expected_sha256`; `null` means the target must not exist. Optional `validate_command` must contain `{path}` for the staged file. Existing owner/mode are retained; backups have strict access permissions. Targets and local transfer paths reject symlinks/junctions. These checks reduce accidental conflicts, not hostile same-account races or changes by external programs. Do not treat redacted output as a complete secret-loss prevention mechanism.

Uploads read from `transfers/` **inside the package directory**. Downloads and plaintext exports live under `transfers/` in the **per-target state directory** instead. Tool outputs include actual download destinations; do not assume they are in the repository. Use `ssh_secret_presence` for `.env` checks rather than reading values.

### Downloads

`ssh_download_file`, `ssh_download_status`, `ssh_download_resume`, `ssh_download_pause`, `ssh_download_list`, `ssh_download_cleanup`, `ssh_download_decrypt`.

Start with `remote_path`, a `local_path` below `transfers/`, and `encrypt: true` for sensitive dumps. Save `transfer_id`; monitor byte progress and resume that same ID after interruption. Changed source identity/checksum or broken encrypted frames fail closed. A pre-download full-file hash can take time before byte progress begins. Protected storage is owner-only on Unix and current Windows user plus SYSTEM on Windows.

Encryption uses framed AES-256-GCM. The Windows key is protected by DPAPI CurrentUser; on Unix it is stored in a private file. This does not defend against code running as the same user, local root/SYSTEM, or a compromised SSH server. It is not a portable backup-key format. `ssh_download_decrypt` explicitly exports verified plaintext and refuses overwriting a destination. That export is **not** auto-deleted by transfer cleanup. Default transfer retention is 7 days, configurable 1-365; expiration cleanup runs while MCP is running and on its next startup, not while it is off. Remote backups/logs need separate retention planning.

### Diagnostics and permissions

`ssh_network_probe`, `ssh_service_status`, `ssh_journal_tail`.

Network probes split DNS/TCP/TLS/SMTP/STARTTLS results and never send mail or credentials. TLS certificates are verified. Network/service diagnostics run as the current SSH account when non-root. When connected as root, they require a dedicated non-root account (`mcp-diagnostics` by default). A root administrator must create this account manually with a locked password, no interactive shell, no sudo and no privileged supplementary groups; configure another existing restricted account using `SSH_DIAGNOSTIC_USER` if appropriate. Missing accounts cause diagnostics to fail, not run as root.

The remaining tools retain the configured SSH account's privileges. `ADMIN` labels and MCP annotations are warnings, **not enforcement**. System services, journal access, file ownership changes and arbitrary sudo depend on actual remote permissions. Avoid passwordless unrestricted sudo if you expect isolation.

## Verification and release

```sh
npm run check
npm test
npm run test:operations
npm run check:release
npm pack --dry-run
```

Tests use generated keys, synthetic secrets and local loopback SSH/agent servers, not production credentials. They cover authentication, host-key verification, configuration/CLI safety, MCP tools, redaction, concurrency and encrypted-transfer framing. Linux-only operation tests execute harmless shell commands in private temporary state to verify phases, reports, deadlines, cancellation, lock owners, pagination and legacy compatibility. They are skipped on other OSes; run them on disposable Linux or in CI. Tests do not constitute an independent audit or a full live deployment test. CI is configured for Windows, macOS and Ubuntu with Node 22/24. [RELEASING.md](RELEASING.md) describes publication and archive checks.

## License

[MIT](LICENSE). Provided without warranty; see [SECURITY.md](SECURITY.md) before granting server access.
