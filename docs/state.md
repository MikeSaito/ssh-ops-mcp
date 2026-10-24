# State and cleanup

`ssh_state_usage` accepts `scope: local|remote|all` (default `all`) and optional `warn_bytes`. Budgets are advisory: no command is blocked and no data is deleted. Counts cover known transfer data, operation metadata, logs and backups. They are not a filesystem quota or a full disk-usage scanner. Unknown/unreadable objects are reported explicitly.

`ssh_state_cleanup` requires `scope: local|remote` and a category: `local_downloads`, `operation_logs` or `file_backups`. Scope and category must match. Every multi-server request also requires `server_id`.

1. Preview with `preview: true` (default), a past timezone-qualified `created_before` and optional `max_items` (1..100, default 100).
2. Inspect the returned candidates and estimated bytes. Nothing has been deleted.
3. Apply with the same server, scope/category, `preview: false` and returned `plan_id` within 15 minutes.

Plans are single-use, including interrupted applications. Preview again after an uncertain application; never invent a new modifying command to compensate. Changed files are skipped. Only known regular files inside MCP state are eligible. Symlinks, active or unknown operations and plaintext exports are excluded. Operation status, request/spec hashes and deduplication records are retained permanently. Reusing a cleaned operation's request ID still does not launch it again.

Remote log cleanup requires both creation and completion before the cutoff. Backup cleanup is a separate explicit category and only accepts backups with complete integrity metadata written by this version. Legacy or incomplete backups are counted as unknown and retained. Download cleanup retains its status record and marks data expired.

Remote cleanup is manual. There is no background SSH cleanup timer. Existing local download expiration is unchanged. Local mutex files are permanent and must not be removed by maintenance.

History uses a private SQLite cache of safe labels, states and times, never commands or output. JSON operation files remain authoritative. Dirty markers recover interrupted cache updates; corrupt indexes fall back to file-based search and are preserved for inspection before rebuilding. A page does not reread every completed operation's JSON. Concurrent arrivals are not a frozen snapshot of the entire history.
