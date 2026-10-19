import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { atomicJson } from '../src/local-state.js';

// Each test file runs in its own process. Restore the filesystem stub before cleanup.
test('atomic JSON replaces the destination without exposing a partial document', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-atomic-'));
  try {
    const file = path.join(dir, 'status.json');
    await atomicJson(file, { generation: 1 });
    await atomicJson(file, { generation: 2 });
    assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { generation: 2 });
    assert.deepEqual(await fs.readdir(dir), ['status.json']);
    if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('Windows atomic JSON retries transient replacement errors and keeps the original until success', { skip: process.platform !== 'win32' }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-atomic-retry-'));
  const rename = fs.rename;
  try {
    const file = path.join(dir, 'status.json');
    await atomicJson(file, { generation: 1 });
    let attempts = 0;
    fs.rename = async (from, to) => {
      attempts++;
      assert.equal(to, file);
      assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { generation: 1 });
      if (attempts <= 3) throw Object.assign(new Error('Synthetic replacement lock'), { code: ['EPERM', 'EACCES', 'EBUSY'][attempts - 1] });
      return rename(from, to);
    };
    await atomicJson(file, { generation: 2 });
    assert.equal(attempts, 4);
    assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { generation: 2 });
    assert.deepEqual(await fs.readdir(dir), ['status.json']);
  } finally { fs.rename = rename; await fs.rm(dir, { recursive: true, force: true }); }
});

test('Windows atomic JSON stops retrying a persistent lock and preserves the original', { skip: process.platform !== 'win32' }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-atomic-fail-'));
  const rename = fs.rename;
  try {
    const file = path.join(dir, 'status.json');
    await atomicJson(file, { generation: 1 });
    let attempts = 0;
    fs.rename = async () => { attempts++; throw Object.assign(new Error('Synthetic persistent lock'), { code: 'EPERM' }); };
    await assert.rejects(atomicJson(file, { generation: 2 }), { code: 'EPERM' });
    assert.equal(attempts, 9);
    assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { generation: 1 });
    assert.deepEqual(await fs.readdir(dir), ['status.json']);
  } finally { fs.rename = rename; await fs.rm(dir, { recursive: true, force: true }); }
});

test('atomic JSON does not retry unrelated failures or hide the error', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-atomic-error-'));
  const rename = fs.rename;
  try {
    const file = path.join(dir, 'status.json');
    await atomicJson(file, { generation: 1 });
    let attempts = 0;
    fs.rename = async () => { attempts++; throw Object.assign(new Error('Synthetic invalid path'), { code: 'ENOENT' }); };
    await assert.rejects(atomicJson(file, { generation: 2 }), { code: 'ENOENT' });
    assert.equal(attempts, 1);
    assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { generation: 1 });
    assert.deepEqual(await fs.readdir(dir), ['status.json']);
  } finally { fs.rename = rename; await fs.rm(dir, { recursive: true, force: true }); }
});
