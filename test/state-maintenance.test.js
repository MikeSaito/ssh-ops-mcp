import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Downloads } from '../src/downloads.js';
import { StateMaintenance } from '../src/state-maintenance.js';
import { atomicJson } from '../src/local-state.js';

test('local cleanup is preview-first, single-use, server-bound and preserves changed/active data', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-maintenance-'));
  try {
    const downloads = new Downloads(root, { SSH_HOST: 'alpha.invalid', SSH_USERNAME: 'test' });
    const maintenance = new StateMaintenance(downloads);
    for (const [n, state] of [[1, 'paused'], [2, 'paused'], [3, 'running']]) {
      const id = n.toString().padStart(32, '0'), dir = downloads.directory(id);
      await fs.mkdir(dir, { recursive: true });
      await atomicJson(path.join(dir, 'status.json'), { state, created_at: 100, expires_at: '2099-01-01T00:00:00Z' });
      await fs.writeFile(path.join(dir, 'data.part'), 'synthetic data');
    }
    const plan = await maintenance.cleanup({ created_before: '2026-01-01T00:00:00Z' });
    assert.equal(plan.candidates.length, 2);
    const changed = '2'.padStart(32, '0');
    await atomicJson(path.join(downloads.directory(changed), 'status.json'), { state: 'paused', created_at: 101 });
    const foreign = new StateMaintenance(new Downloads(root, { SSH_HOST: 'beta.invalid', SSH_USERNAME: 'test' }));
    await assert.rejects(foreign.cleanup({ preview: false, plan_id: plan.plan_id }), /another server/);
    const result = await maintenance.cleanup({ preview: false, plan_id: plan.plan_id });
    assert.equal(result.removed.length, 1); assert.equal(result.skipped.length, 1);
    await assert.rejects(maintenance.cleanup({ preview: false, plan_id: plan.plan_id }), /already applied/);
    assert.equal((await downloads.status('1'.padStart(32, '0'))).state, 'expired');
    assert.equal(await fs.readFile(path.join(downloads.directory(changed), 'data.part'), 'utf8'), 'synthetic data');
    const usage = await maintenance.usage(1);
    assert.equal(usage.unknown_count, 1); assert.equal(usage.warning, 'state_budget_exceeded');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
