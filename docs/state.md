# State and cleanup

## Local audit

Each audited tool call writes a requested record and a final record to the selected profile's private `audit.jsonl`. A generated `call_id` pairs them even when calls for the same operation overlap. Existing records without these fields remain valid.

Final records add `duration_ms`: monotonic elapsed time inside the tool handler, including connection setup and remote waits but excluding audit writes and client delivery. This is a call measurement, not the lifetime of a durable remote operation.

Errors use a fixed `error_code` catalog for SSH connection/authentication/host verification, transport, helper, resource-lock and common filesystem failures. Unknown codes become `unclassified_error`; their text and values are not recorded. Known transport failures may add `phase` and `dispatch_state` (`not_sent` or `unknown`). Connection loss does not prove an operation stopped.

`ssh_exec` and `ssh_server_info` record numeric `exit_code` and mark nonzero exits with `remote_exit_nonzero`. Operation responses may add `operation_state`; unavailable status responses carry a safe error code even though the handler returned normally. The existing `returned` outcome means a handler returned, not that its command or operation succeeded.

Commands, arguments, contents, output, raw errors and arbitrary diagnostic values are excluded. The writer validates new fields independently. Rotation stays at 5 MB with one previous file. A missing final record can mean interruption or audit failure; do not replay modifying work from audit records. An initial audit failure blocks dispatch, and a final audit failure preserves the action result with a warning.

`ssh_state_usage` accepts `scope: local|remote|all` (default `all`) and optional `warn_bytes`. Budgets are advisory: no command is blocked and no data is deleted. Counts cover known transfer data, operation metadata, logs and backups. They are not a filesystem quota or a full disk-usage scanner. Unknown/unreadable objects are reported explicitly.

`ssh_state_cleanup` requires `scope: local|remote` and a category: `local_downloads`, `operation_logs` or `file_backups`. Scope and category must match. Every multi-server request also requires `server_id`.

1. Preview with `preview: true` (default), a past timezone-qualified `created_before` and optional `max_items` (1..100, default 100).
2. Inspect the returned candidates and estimated bytes. Nothing has been deleted.
3. Apply with the same server, scope/category, `preview: false` and returned `plan_id` within 15 minutes.

Plans are single-use, including interrupted applications. Preview again after an uncertain application; never invent a new modifying command to compensate. Changed files are skipped. Only known regular files inside MCP state are eligible. Symlinks, active or unknown operations and plaintext exports are excluded. Operation status, request/spec hashes and deduplication records are retained permanently. Reusing a cleaned operation's request ID still does not launch it again.

Remote log cleanup requires both creation and completion before the cutoff. Backup cleanup is a separate explicit category and only accepts backups with complete integrity metadata written by this version. Legacy or incomplete backups are counted as unknown and retained. Download cleanup retains its status record and marks data expired.

Remote cleanup is manual. There is no background SSH cleanup timer. Existing local download expiration is unchanged. Local mutex files are permanent and must not be removed by maintenance.

History uses a private SQLite cache of safe labels, states and times, never commands or output. JSON operation files remain authoritative. Dirty markers recover interrupted cache updates; corrupt indexes fall back to file-based search and are preserved for inspection before rebuilding. A page does not reread every completed operation's JSON. Concurrent arrivals are not a frozen snapshot of the entire history.
