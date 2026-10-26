# Setup, access policy and SSH routes

Install Node.js 22.13+ and run `npm ci` in the source directory. Credentials stay in a private directory outside this checkout. No installer writes client settings or changes your ACLs.

## Check the environment

```sh
node -- bin/ssh-ops-mcp.js --servers-file /absolute/private/servers.json --doctor
node -- bin/ssh-ops-mcp.js --servers-file /absolute/private/servers.json --check-config
node -- bin/ssh-ops-mcp.js --servers-file /absolute/private/servers.json --print-client-config
```

Doctor is local by default: Node/SQLite, connection configuration, credential permissions, existing state permissions and parent writability. Missing state is not created. It reports booleans and safe metadata, without credential values. An unpinned host produces a warning. It cannot prove that an agent contains a working key without connecting.

An explicit probe checks authentication/host key, Linux, Python 3.8+, bash, optional sqlite3 and opening SFTP, without changing remote files:

```sh
node -- bin/ssh-ops-mcp.js --servers-file /absolute/private/servers.json --doctor --connect --server-id staging
```

The selected target must allow `ssh_server_info` when a policy is used. Failed required checks return exit code 1. No automatic reconnect, credential rotation or remediation runs.

For one connection use `--connection-file /absolute/private/server.env`. The old `--env-file` is accepted after `node -- ENTRY`; without the separator some Node versions process it themselves before MCP starts. Generated client configuration includes the separator and file paths, never credentials. Review it before adding it to your client.

## Limit one MCP launch

Create an access policy outside the checkout. Tool names are exact and case-sensitive; wildcards, duplicates and unknown names fail startup. Unlisted servers and tools are denied. For legacy single-server mode use the server ID `default`.

```json
{
  "version": 1,
  "servers": {
    "prod": { "tools": ["ssh_server_info", "ssh_file_hash", "ssh_read_file"] },
    "staging": { "tools": ["ssh_server_info", "ssh_exec", "ssh_file_hash", "ssh_edit_file"] }
  },
  "transit_servers": []
}
```

```sh
node -- bin/ssh-ops-mcp.js --servers-file /absolute/private/servers.json --policy-file /absolute/private/access-policy.json
```

`SSH_MCP_POLICY_FILE` is the environment equivalent. The policy is read at startup; restart MCP to apply changes. Discovery lists only allowed target profiles. Target credentials excluded by policy are not read. Tools allowed on at least one target appear in discovery, but every call checks the chosen server again before opening SSH. `ssh_servers_list` remains available for the allowed targets. A launch without a policy preserves unrestricted tool access to its configured accounts.

Granting `ssh_exec` or a write tool can grant arbitrary code execution as the SSH user. A tool policy does not limit shell commands, paths or root privileges. It is not a replacement for restricted remote users and OS permissions. A local user who can alter the MCP launch or files can choose a different policy. Read-only launches skip automatic download cleanup, but MCP may create private local state/audit files.

## File permissions

Unix credentials require mode 0600 or stricter. Manifest/policy files may be readable by others, but cannot be writable by other users. Existing state directories require mode 0700 or stricter. Credential files and state roots cannot be symlinks.

On Windows, ACLs are checked on the file/directory and direct parent before use. The current user, SYSTEM and local Administrators are trusted. Foreign access to confidential data, replacement rights, unsafe owners, null DACLs and unsupported ACE types cause a failure. This is a conservative allow-list, not full effective-permission calculation; a deny ACE does not cancel an unsafe allow for this check. The program does not repair existing permissions. Use a trusted private parent directory and inspect ACLs yourself if a check fails. Same-user code and privileged administrators remain trusted.

## One bastion

Add `via` to a target profile. Each side uses its own password, key or agent and verified host fingerprint. Relative paths still resolve from the manifest/env file containing them.

```json
{
  "version": 1,
  "servers": [
    { "id": "jump", "env_file": "jump.env" },
    { "id": "private-app", "env_file": "private-app.env", "via": "jump" }
  ]
}
```

With a policy, explicitly allow transit separately. Transit-only profiles are not exposed as command targets:

```json
{
  "version": 1,
  "servers": { "private-app": { "tools": ["ssh_server_info", "ssh_exec"] } },
  "transit_servers": ["jump"]
}
```

The bastion must permit SSH `direct-tcpip` forwarding to the target address and port. The bastion resolves the target hostname. There is one hop, no chains, cycles, `~/.ssh/config`, ProxyCommand or automatic direct fallback. Failure affects that route only. The target handshake runs inside the forwarding channel and independently verifies its key; agent forwarding is disabled on both connections.

Direct state paths and request IDs retain their algorithms. A routed connection has separate local state and request IDs. Changing the bastion selects different routed state. The same physical account reached by different routes still shares remote filesystem permissions; use consistent resources for cooperative deploy locks. Download workers snapshot the target and its required bastion over IPC, not unrelated profiles. Editing config files does not redirect an active worker.

## Search and exact edits

`ssh_find_files` accepts an absolute `path`, optional `pattern`, `max_depth` and `max_results`. Patterns use Python `fnmatch` against relative paths or basenames. `ssh_search_text` adds literal `text` and optional `case_sensitive: false`; matching is per UTF-8 line, not regular expressions. Results include path, line number and a redacted excerpt.

Defaults: depth 8, 100 results, hidden/common secret files skipped. Explicit `include_hidden` and `include_sensitive` opt in separately. Searches never follow symlink entries or cross filesystems. Limits: depth 32, 1,000 results, 10,000 visited entries, 10 seconds of traversal, 1 MiB per text file, 16 MiB total input and about 64 KiB of output. Binary/non-UTF-8 files are skipped. Check `truncated`, `skipped` and `scanned_bytes`; a partial search does not establish absence. Redaction is not a guarantee against disclosure.

To edit an existing UTF-8 file:

1. Get the current SHA-256 with `ssh_file_hash`.
2. Call `ssh_edit_file` with that `expected_sha256`, `edits` and default `preview: true`.
3. Review the diff. Apply the same edit with `preview: false`; use `validate_command` with `{path}` to validate the staged file.

```json
{
  "server_id": "staging",
  "path": "/srv/demo/config.txt",
  "expected_sha256": "REPLACE_WITH_CURRENT_HASH",
  "edits": [{ "old_text": "enabled=false", "new_text": "enabled=true", "expected_matches": 1 }],
  "preview": true
}
```

Edits apply in order to original server-side text; there must be exactly `expected_matches` occurrences for each step. Ambiguity, hash mismatch, binary data, oversized output or validation failure preserves the original. Unchanged BOM/CRLF are retained. Existing ownership/mode, private backups and atomic replacement follow `ssh_write_file`. Do not paste a redacted `[REDACTED]` value back into an edit. Maximum 50 edits, 100 matches per edit and 5 MiB output.

## Verification and measurements

`npm run check:install` packages and installs source into a temporary directory, then checks the installed CLI. It needs npm registry access for dependencies and removes its temporary files.

`npm run test:real-ssh` requires Docker. It creates Debian OpenSSH, Alpine OpenSSH, Dropbear, a missing-SFTP fixture and a target reachable only through the bastion. Networks are internal, ports are not published and all keys/passwords are generated or synthetic. The runner cleans up its own resources; it never connects to configured production servers. `SSHOPS_TEST_NODE=24` selects the pinned Node.js 24 test image; default is 22.

`npm run bench:ssh` adds 20 sequential samples per measurement: configuration/TCP/handshake/authentication, per-call helper, retained-transport helper prototype and per-call MCP. These local container timings are not Internet latency claims. Production pooling is not enabled: the prototype does not validate pooled MCP cancellation, concurrent leases or memory limits. Reusing a transport must never imply replaying an uncertain command. Interactive sessions and user tunnels remain deferred until a concrete need.
