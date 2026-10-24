import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Downloads } from '../src/downloads.js';
import { atomicJson, tryLocalLock } from '../src/local-state.js';

test('transfer list sorts before limiting, tolerates corruption and binds cursors', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-list-'));
  try {
    const downloads = new Downloads(root, { SSH_HOST: 'example.invalid', SSH_USERNAME: 'test' });
    for (let n = 0; n < 105; n++) {
      const id = n.toString(16).padStart(32, '0'), dir = downloads.directory(id);
      await fs.mkdir(dir, { recursive: true });
      await atomicJson(path.join(dir, 'status.json'), { state: 'completed', created_at: 200000 - n, total_bytes: 2 });
    }
    await fs.writeFile(path.join(downloads.directory('0'.repeat(32)), 'status.json'), '{broken');
    const first = await downloads.list();
    assert.equal(first.transfers.length, 100); assert.equal(first.unavailable_count, 1);
    assert.equal(first.transfers[0].transfer_id, '1'.padStart(32, '0')); assert.ok(first.more);
    const second = await downloads.list({ cursor: first.next_cursor });
    assert.equal(second.transfers.length, 4); assert.equal(second.more, false);
    assert.ok(!first.transfers.some(x => second.transfers.some(y => x.transfer_id === y.transfer_id)));
    await assert.rejects(downloads.list({ cursor: first.next_cursor, states: ['completed'] }), /cursor/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
test('worker liveness uses its OS lease, never a reused PID', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-worker-')), id = 'f'.repeat(32);
  try {
    const downloads = new Downloads(root); await fs.mkdir(downloads.directory(id), { recursive: true });
    await atomicJson(path.join(downloads.directory(id), 'status.json'), { state: 'running', lease_version: 1, worker_pid: process.pid });
    assert.equal((await downloads.status(id)).state, 'interrupted');
    const release = await tryLocalLock(path.join(downloads.directory(id), 'worker.lock'));
    try { assert.equal((await downloads.status(id)).state, 'running'); } finally { release(); }
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
