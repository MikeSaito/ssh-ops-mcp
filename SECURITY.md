# Security

## Trust boundaries

This program intentionally grants arbitrary shell/file access to the selected SSH account. A model, MCP client, injected prompt or compromised local process able to call these tools can exercise those permissions. A root account or unrestricted sudo means effectively full control. No command filter, annotation, read-only hint, deployment lock or client approval is an OS sandbox. Restrict accounts, authorized keys, filesystem rights, network access and sudo policy on the server; keep backups and a separate recovery path.

The server runs locally over stdio and does not listen on a network port. Never wrap it in unauthenticated HTTP or share an env file with untrusted chats/users. Global client registration can make tools available to other local chats. Multi-user access needs its own authenticated gateway and account isolation, which this release does not provide.

## Controls

Without a policy, clients can call tools for every configured profile. An optional startup policy limits exposed target IDs and tools and separately authorizes transit-only servers. Enforcement happens before audit/SSH dispatch, not just tool discovery. This limits this MCP process, not the client's filesystem access or the remote account's OS permissions. Someone able to modify local policy, credentials or launch commands can choose another policy. Use explicit IDs to avoid accidental targeting, and restrict each account on its server. Profiles are loaded at startup; workers retain only the selected connection snapshot over IPC, without inheriting other SSH credentials. State isolation uses normalized host/port/user, not DNS resolution. Different aliases of one host may still represent the same remote account and state.

- Pinned SHA-256 server host keys by default. Explicit unverified mode is development-only. Fingerprints must come through an independently trusted channel.
- Explicit SSH user/authentication mode; no automatic root, auth fallback or agent forwarding. Key/password/passphrase files are bounded regular files; Unix public permissions are rejected. Windows file and direct-parent ACLs are conservatively checked before use. Current user, SYSTEM and local Administrators are trusted; unsupported ACEs, foreign dangerous allow rules, foreign owners and null DACLs are rejected. This is an allow-list check, not a general effective-access evaluator. Existing ACLs are never repaired automatically.
- Diagnostic DNS/service tools do not run as root. Privileged execution/file/journal tools retain the SSH account's actual rights.
- Hash-checked staged writes, validation, private backups and symlink rejection. Filesystem changes by other programs or a malicious same-account process are not transactional.
- Private local download storage, source/hash checks and optional AES-256-GCM framing. Windows DPAPI protects stored keys for the current user; Unix keys are stored under owner-only permissions.
- Audit entries omit commands, arguments, contents, stdout and raw errors. Redaction handles common formats and loaded connection secrets, but cannot reliably detect every secret, encoding, binary output or unusual configuration format.

## Known limits

Plaintext passwords/passphrases still exist in process memory and may live in env files; this is not an OS credential vault. Download workers receive only the selected connection snapshot over IPC and a filtered system environment, not the other profiles' credentials. Local code running as the same user, remote root, local root/SYSTEM and a compromised client remain trusted. SSH can protect transit, not the behavior of a compromised endpoint.

Operations are deduplicated launches, not database transactions. Disconnect/timeout is not a rollback. Commands can deliberately detach processes outside cancellation groups. Deploy locks are per remote account and cooperatively used; arbitrary shell commands can bypass them. Do not replay unknown modifying work automatically.

Sensitive downloads are plaintext unless `encrypt: true` is requested. Explicit plaintext exports outlive transfer cleanup. Cleanup only runs while MCP is alive or at next startup. Remote state, operation output, command specifications and file backups are private but may contain secrets and do not auto-expire. Adopt your own remote retention policy and encrypt/offline backup strategy. Audit files disclose server identity and action timing; consider them private too.

Tool outputs remain text blocks, sometimes containing JSON; `structuredContent` is not supplied. One-hop bastions use independent authentication and host-key checks, never direct fallback; workers receive the selected target plus its required bastion. Production transport pooling, interactive terminals, user tunnels, SSH MFA, SSH configuration/certificates, remote Windows helpers and a hosted/cloud endpoint are not implemented. Synthetic loopback and real OpenSSH/Dropbear tests are not an independent security audit or proof of compatibility with every hardware-key implementation.

Search skips symlinks, other filesystems, hidden and common secret files by default, and bounds work and output. These are convenience controls, not a remote filesystem sandbox. ACL and pathname checks do not defend against every hostile ancestor replacement or trusted same-user process. Keep source, configuration and their directories private and trusted.

## Reporting

Local mutexes require a local filesystem with working SQLite locks, not a network share. Keep permanent mutex files; stop every old instance/worker before migration. Audit failure before dispatch prevents execution; final audit failure produces a warning while retaining the original result. A warning is not permission to replay a command.

Remote maintenance is manual and preview-first. It never removes operation status/spec hashes or unlocks unknown work. It rechecks known file identities and content before removal, but it is not a transaction against arbitrary malicious same-account filesystem changes. Backups without complete integrity metadata are retained. State usage reports managed categories, not every byte on the server.

Do not report credentials or exploitable details in a public issue. The repository owner should enable GitHub private vulnerability reporting before publication; once enabled, use the Security tab's private reporting flow. If unavailable, request a private contact channel without disclosing the vulnerability publicly. Supply synthetic reproduction data and rotate any accidentally disclosed credential immediately. Current release line: 1.x; no support SLA or audited-security claim.
