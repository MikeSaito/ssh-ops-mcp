import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { encryptFrame, scanPartial, MAGIC } from '../src/encrypted-file.js';
import { privateDirectory, sealKey, openKey } from '../src/local-state.js';

test('private key is recoverable without putting plaintext key in metadata on Windows', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-private-'));
  try {
    await privateDirectory(root);
    const key = crypto.randomBytes(32), sealed = await sealKey(key);
    if (process.platform === 'win32') { assert.equal(sealed.scheme, 'windows-dpapi-current-user'); assert.notEqual(sealed.value, key.toString('base64')); }
    assert.deepEqual(await openKey(sealed), key);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
test('encrypted resume validates frames and handles only a torn trailing frame', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-cipher-'));
  const key = crypto.randomBytes(32), id = '1'.repeat(32);
  const first = Buffer.from('synthetic-secret-one'), second = Buffer.from('Привет, мир');
  const bytes = Buffer.concat([MAGIC, encryptFrame(key, id, 0, first), encryptFrame(key, id, first.length, second)]);
  try {
    const file = path.join(root, 'part'); await fs.writeFile(file, bytes);
    assert.ok(!bytes.includes(first));
    let handle = await fs.open(file, 'r+'); const recovered = [];
    const result = await scanPartial(handle, key, id, chunk => recovered.push(chunk));
    assert.deepEqual(Buffer.concat(recovered), Buffer.concat([first, second])); assert.equal(result.complete, true); await handle.close();
    await fs.writeFile(file, bytes.subarray(0, bytes.length - 2)); handle = await fs.open(file, 'r+');
    const partial = await scanPartial(handle, key, id); assert.equal(partial.position, first.length); assert.equal(partial.complete, false); await handle.close();
    const corrupt = Buffer.from(bytes); corrupt[MAGIC.length + 20] ^= 1; await fs.writeFile(file, corrupt); handle = await fs.open(file, 'r');
    await assert.rejects(scanPartial(handle, key, id)); await handle.close();
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
