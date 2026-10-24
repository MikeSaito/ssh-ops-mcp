import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { atomicJson, tryLocalLock, localLock } from '../src/local-state.js';
import { spawn } from 'node:child_process';

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

test('atomic JSON removes temp after write/sync failure and preserves the first error', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-write-fail-')), open = fs.open;
  try {
    const file = path.join(dir, 'state.json'); await atomicJson(file, { old: true });
    fs.open = async (...args) => {
      const handle = await open(...args);
      return { writeFile: async () => { throw Object.assign(new Error('write failed'), { code: 'ENOSPC' }); }, close: () => handle.close() };
    };
    await assert.rejects(atomicJson(file, {}), { code: 'ENOSPC' });
    assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { old: true });
    assert.deepEqual(await fs.readdir(dir), ['state.json']);
  } finally { fs.open = open; await fs.rm(dir, { recursive: true, force: true }); }
});

test('OS mutex excludes concurrent callers and releases after forced process exit', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-mutex-'));
  const file = path.join(dir, 'test.lock');
  const module = new URL('../src/local-state.js', import.meta.url).href;
  const child = spawn(process.execPath, ['--input-type=module', '-e', `import {tryLocalLock} from ${JSON.stringify(module)}; await tryLocalLock(${JSON.stringify(file)}); process.send('locked'); setInterval(()=>{},1000);`], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  try {
    await new Promise((resolve, reject) => { child.once('message', resolve); child.once('error', reject); child.once('exit', code => reject(new Error('Child exited ' + code))); });
    assert.equal(await tryLocalLock(file), null);
    await assert.rejects(localLock(file, () => assert.fail('must not run'), 60), /busy/);
    const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGKILL'); await exited;
    const release = await tryLocalLock(file); assert.equal(typeof release, 'function'); release();
    assert.ok((await fs.stat(file + '.mutex.sqlite')).isFile());
  } finally { child.kill(); await fs.rm(dir, { recursive: true, force: true }); }
});

test('ownerless legacy locks are retained, active legacy owners block migration', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-legacy-')), file = path.join(dir, 'test.lock');
  try {
    await fs.mkdir(file);
    await localLock(file, async () => {});
    assert.ok((await fs.stat(file)).isDirectory());
    await atomicJson(path.join(file, 'owner.json'), { pid: process.pid });
    await assert.rejects(tryLocalLock(file), /legacy MCP/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
