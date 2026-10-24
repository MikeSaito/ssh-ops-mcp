# Local recovery

Node.js 22.13 or later is required. The built-in SQLite module is experimental in Node.js 22. No extra SQLite package or server is installed.

Stop all older MCP instances and download workers before updating. Pause active transfers and wait for a paused status first. Do not mix versions sharing one state directory. Existing IDs, manifests and download data are preserved. Old lock directories are retained; live legacy owners block migration. Missing or corrupt legacy owner metadata is not proof that an old process stopped: verify the shutdown yourself.

Local mutexes are SQLite transactions on persistent private files. Process exit releases the OS lock. Never remove mutex files to unlock a resource. A corrupt or inaccessible mutex is an error, not evidence that a worker stopped. Reusing a PID cannot make a new download worker own an old transfer.

An unavailable initial audit prevents execution. Failure to save the final audit adds a separate `audit_write_failed` text block without replacing the command result or operation ID. Do not replay an action because its audit failed.

`ssh_download_list` supports `limit` (1..100, default 100), `states` and `cursor`. Results are newest first and include `created_at`, `next_cursor`, `more` and `unavailable_count`. Reuse cursors with the same profile and filters. Corrupt entries are counted, not exposed. Entries without creation time sort last.
