# Preparing a GitHub release

This guide covers validation, source distribution and GitHub releases.

1. Review README, SECURITY and LICENSE. Choose a GitHub repository name (suggested: `ssh-ops-mcp`) and verify rights to distribute the code. Enable private vulnerability reporting and secret scanning/push protection where available.
2. Keep all credentials outside this folder. Run `npm ci`, `npm run check`, `npm test`, `npm run check:release` and `npm pack --dry-run`. Inspect the complete candidate file list; the built-in hygiene checker is supplemental, not a comprehensive secret scanner.
3. Before committing, inspect `git status` and `git diff --cached`; do not add credentials or runtime files with `-f`.
4. Set the Git remote and package repository metadata to the actual GitHub repository URL. Review the staged files and commit author information before pushing.
5. Wait for the complete GitHub CI matrix to succeed. For operational changes, additionally test with an explicitly authorized disposable Linux server, not production.
6. Create an annotated `v1.1.0` tag and GitHub Release using CHANGELOG.md. A clean source ZIP should come from the tag (`git archive --format=zip --output=ssh-ops-mcp-1.1.0-source.zip v1.1.0`), not a recursive copy of your working folder. Optional distributable: `npm pack` builds a local tarball with the package's explicit file allow-list, without publishing to npm. Attach a checksum if distributing a custom artifact.

The package remains `private: true` to prevent accidental npm publication; GitHub source distribution and local `npm pack` still work. Registry publication requires a separate deliberate review of the name, metadata, ownership and publishing credentials. CI has read-only permissions, no SSH secrets and no deploy/release side effects. Dependabot is configured for npm and pinned GitHub Actions updates.

## Release checklist

- [ ] Only source/docs/examples/tests; no env secrets, private keys, personal paths, dumps or runtime state
- [ ] License and security policy reviewed; private reporting enabled on the actual GitHub repository
- [ ] Local tests and target-platform CI green
- [ ] Auth methods and host-key failure tested; no claimed unverified hardware/MFA/jump-host support
- [ ] Clean tag/archive file listing reviewed; version and changelog match
- [ ] Actual repository URL added to package metadata only after one exists
