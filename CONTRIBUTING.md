# Contributing

Use Node 22+ and `npm ci`. Before submitting a change, run `npm run check`, `npm test`, `npm run test:operations`, `npm run check:release` and `npm pack --dry-run`. Python operation tests require Linux and private temporary directories; on other OSes they are skipped. CI also parses the Python helper. Offline tests generate their own keys and loopback servers; they must never load real SSH credentials or execute on production.

Keep secret files outside the repository. Do not commit `.env`, private keys, `.codex`, transfer state, archives, real logs, identifying server details or absolute personal paths. Use documentation-only addresses and synthetic fixtures. Never enable `pull_request_target` to run untrusted code with secrets. Do not add auto-retries for commands with unknown effects.

Add regression tests for auth/host verification, concurrency, unknown outcomes and filesystem integrity when changing those boundaries. Keep stdout reserved for MCP protocol during normal server operation; diagnostics go to stderr. Preserve the text response interface unless a deliberate compatibility change is documented. Linux remote helper integration needs a disposable server and explicit operator authorization; do not infer permission from offline tests.

Use a clear PR description including risks and verification. See SECURITY.md for private vulnerability reporting. Please keep English user docs up to date; Russian docs should track important behavior and security limitations.
