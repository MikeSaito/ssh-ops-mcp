import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { redact, transferPath, audit } from '../src/security.js';
import { localLock, atomicJson, readJson } from '../src/local-state.js';

const fixtures = JSON.parse(await fs.readFile(new URL('./redaction-fixtures.json', import.meta.url), 'utf8'));
for (const [index, fixture] of fixtures.entries()) test('redaction preserves scalar/YAML/JSON structure ' + index, () => {
  assert.equal(redact(fixture.input), fixture.output);
  assert.equal(redact(fixture.output), fixture.output, 'redaction is idempotent');
});

test('local manifests and audit serialize concurrent callers', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-concurrency-'));
  try {
    const manifest = path.join(root, 'manifest.json');
    await atomicJson(manifest, { count: 0 });
    await Promise.all(Array.from({ length: 12 }, () => localLock(manifest + '.lock', async () => {
      const value = await readJson(manifest); await atomicJson(manifest, { count: value.count + 1 });
    })));
    assert.equal((await readJson(manifest)).count, 12);
    await Promise.all(Array.from({ length: 12 }, () => audit(root, { tool: 'test', outcome: 'returned' })));
    assert.equal((await fs.readFile(path.join(root, 'audit.jsonl'), 'utf8')).trim().split('\n').length, 12);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('secrets are removed from env/json/authorization/private keys', () => {
  const text = 'SSH_PASSWORD="abc xyz"\n{"API_KEY":"test-secret"}\nAuthorization: Bearer qwerty\n-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-data\n-----END OPENSSH PRIVATE KEY-----';
  const safe = redact(text);
  for (const value of ['abc xyz', 'test-secret', 'qwerty', 'private-data']) assert.ok(!safe.includes(value));
});
test('literal SSH password redaction handles regular-expression punctuation', () => {
  process.env.SSH_PASSWORD = 'test.$(secret)';
  assert.equal(redact('prefix test.$(secret) suffix'), 'prefix [REDACTED] suffix');
  delete process.env.SSH_PASSWORD;
});
test('transfers exclude configuration, traversal and symlinks', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-test-'));
  try {
    await assert.rejects(transferPath(root, '../escape'));
    await assert.rejects(transferPath(root, '.env'));
    assert.equal(await transferPath(root, 'transfers/nested/file', true), path.join(root, 'transfers/nested/file'));
    await fs.symlink(os.tmpdir(), path.join(root, 'transfers/junction'), process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(transferPath(root, 'transfers/junction/file'));
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
test('audit excludes arguments, commands, raw errors and contents', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-audit-'));
  try {
    await audit(root, { tool: 'ssh_write_file', outcome: 'returned', command: 'secret123', content: 'secret456' });
    const text = await fs.readFile(path.join(root, 'audit.jsonl'), 'utf8');
    assert.ok(!text.includes('secret123') && !text.includes('secret456'));
    assert.equal(JSON.parse(text).tool, 'ssh_write_file');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
