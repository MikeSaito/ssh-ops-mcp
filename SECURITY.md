# Security

## Trust boundaries

This program intentionally grants arbitrary shell/file access to the selected SSH account. A model, MCP client, injected prompt or compromised local process able to call these tools can exercise those permissions. A root account or unrestricted sudo means effectively full control. No command filter, annotation, read-only hint, deployment lock or client approval is an OS sandbox. Restrict accounts, authorized keys, filesystem rights, network access and sudo policy on the server; keep backups and a separate recovery path.

The server runs locally over stdio and does not listen on a network port. Never wrap it in unauthenticated HTTP or share an env file with untrusted chats/users. Global client registration can make tools available to other local chats. Multi-user access needs its own authenticated gateway and account isolation, which this release does not provide.

## Controls

- Pinned SHA-256 server host keys by default. Explicit unverified mode is development-only. Fingerprints must come through an independently trusted channel.
- Explicit SSH user/authentication mode; no automatic root, auth fallback or agent forwarding. Key/password/passphrase files are bounded regular files; Unix public permissions are rejected. Windows credential ACLs remain the administrator's responsibility.
- Diagnostic DNS/service tools do not run as root. Privileged execution/file/journal tools retain the SSH account's actual rights.
- Hash-checked staged writes, validation, private backups and symlink rejection. Filesystem changes by other programs or a malicious same-account process are not transactional.
- Private local download storage, source/hash checks and optional AES-256-GCM framing. Windows DPAPI protects stored keys for the current user; Unix keys are stored under owner-only permissions.
- Audit entries omit commands, arguments, contents, stdout and raw errors. Redaction handles common formats and loaded connection secrets, but cannot reliably detect every secret, encoding, binary output or unusual configuration format.

## Known limits

Plaintext passwords/passphrases still exist in process memory and may live in env files; this is not an OS credential vault. Child download workers inherit the connection environment. Local code running as the same user, remote root, local root/SYSTEM and a compromised client remain trusted. SSH can protect transit, not the behavior of a compromised endpoint.

Operations are deduplicated launches, not database transactions. Disconnect/timeout is not a rollback. Commands can deliberately detach processes outside cancellation groups. Deploy locks are per remote account and cooperatively used; arbitrary shell commands can bypass them. Do not replay unknown modifying work automatically.

Sensitive downloads are plaintext unless `encrypt: true` is requested. Explicit plaintext exports outlive transfer cleanup. Cleanup only runs while MCP is alive or at next startup. Remote state, operation output, command specifications and file backups are private but may contain secrets and do not auto-expire. Adopt your own remote retention policy and encrypt/offline backup strategy. Audit files disclose server identity and action timing; consider them private too.

Tool outputs remain text blocks, sometimes containing JSON; `structuredContent` is not supplied. This release does not implement SSH MFA, jump hosts, SSH configuration/certificates, remote Windows helpers or a hosted/cloud MCP endpoint. Generated-key loopback tests are not an independent security audit or proof of compatibility with every SSH-agent/hardware-key implementation.

## Reporting

Do not report credentials or exploitable details in a public issue. The repository owner should enable GitHub private vulnerability reporting before publication; once enabled, use the Security tab's private reporting flow. If unavailable, request a private contact channel without disclosing the vulnerability publicly. Supply synthetic reproduction data and rotate any accidentally disclosed credential immediately. Current release line: 1.x; no support SLA or audited-security claim.
