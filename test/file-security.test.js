import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { validateAcl, readSecureFile } from '../src/file-security.js';

const sid = 'S-1-5-21-100', foreign = 'S-1-5-32-545';
const report = (rules = [], extras = {}) => ({ current_sid: sid, entries: [{ owner: sid, null_dacl: false, parent: false, rules, ...extras }] });
const allow = (mask, who = foreign) => ({ sid: who, mask, type: 'Allow', inherit_only: false });
test('ACL check rejects foreign readers, writers, owners, null DACL and unknown ACEs', () => {
  validateAcl(report([allow(2032127, sid)]));
  validateAcl(report());
  assert.throws(() => validateAcl(report([allow(1)])), /untrusted/);
  assert.throws(() => validateAcl(report([allow(2)]), false), /untrusted/);
  assert.throws(() => validateAcl(report([], { null_dacl: true })), /DACL/);
  assert.throws(() => validateAcl(report([], { owner: foreign })), /owner/);
  assert.throws(() => validateAcl(report([{ ...allow(1), type: 'Callback' }])), /Unsupported/);
  validateAcl(report([allow(1)]), false);
  assert.throws(() => validateAcl(report([allow(64)], { parent: true })), /untrusted/);
  assert.throws(() => validateAcl(report([allow(0x40000000)], { parent: true })), /untrusted/);
  assert.throws(() => validateAcl(report([allow(0x10000)], { parent: true })), /untrusted/);
  assert.throws(() => validateAcl(report([allow(4)], { parent: true })), /untrusted/);
  assert.throws(() => validateAcl(null));
});
test('secure read preserves bytes and rejects symlinks and oversized files', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-secure-')), file = path.join(dir, 'input');
  try {
    await fs.writeFile(file, 'synthetic-value', { mode: 0o600 });
    assert.equal((await readSecureFile(file)).toString(), 'synthetic-value');
    await assert.rejects(readSecureFile(file, { limit: 2 }), /bounded/);
    if (process.platform !== 'win32') {
      await fs.chmod(file, 0o644); await assert.rejects(readSecureFile(file), /0600/);
    }
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
