import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { atomicJson, readJson, privateDirectory, localLock, fileIdentity } from './local-state.js';
import { connectionIdentity } from './config.js';
import { transferPath } from './security.js';

const idPattern = /^[a-f0-9]{32}$/;
const safeStates = new Set(['completed', 'paused', 'interrupted', 'source_changed', 'integrity_failed']);
const known = ['status.json', 'data.part', 'key.json', 'pause'];

export class StateMaintenance {
  constructor(downloads) { this.downloads = downloads; this.root = downloads.root; this.plans = path.join(this.root, 'cleanup-plans'); this.target = connectionIdentity(downloads.env); }
  async inspect(id) {
    const dir = this.downloads.directory(id);
    if ((await fs.lstat(dir)).isSymbolicLink()) throw new Error('Unsafe transfer directory.');
    const stateFile = path.join(dir, 'status.json');
    if ((await fs.lstat(stateFile)).isSymbolicLink()) throw new Error('Unsafe transfer manifest.');
    const bytesState = await fs.readFile(stateFile), state = JSON.parse(bytesState);
    this.downloads.checkTarget(state);
    let bytes = 0;
    for (const name of known) {
      const info = await fs.lstat(path.join(dir, name)).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
      if (info && (!info.isFile() || info.isSymbolicLink())) throw new Error('Unsafe transfer file.');
      bytes += info?.size || 0;
    }
    if (state.state === 'completed') {
      const destination = await transferPath(this.root, state.local_path);
      if (destination !== state.destination || await fileIdentity(destination) !== state.destination_identity) throw new Error('Published transfer changed.');
      bytes += (await fs.stat(destination)).size;
    }
    return { id, state, eligible: safeStates.has(state.state), bytes, unknown: !safeStates.has(state.state) && state.state !== 'expired',
      fingerprint: await this.downloads.cleanupFingerprint(id, state) };
  }
  async entries() {
    const entries = await fs.readdir(this.downloads.base).catch(error => { if (error.code === 'ENOENT') return []; throw error; });
    const result = []; let unavailable = 0;
    for (const id of entries.filter(x => idPattern.test(x))) {
      try { result.push(await this.inspect(id)); } catch { unavailable++; }
    }
    return { result, unavailable };
  }
  async usage(warnBytes) {
    const { result, unavailable } = await this.entries();
    const bytes = result.reduce((total, x) => total + x.bytes, 0);
    return { category: 'local_downloads', bytes, count: result.length, unknown_count: result.filter(x => x.unknown).length + unavailable,
      partial: unavailable > 0, warning: warnBytes && bytes > warnBytes ? 'state_budget_exceeded' : null };
  }
  async cleanup({ preview = true, plan_id, created_before, max_items = 100 }) {
    if (!preview) {
      if (!idPattern.test(plan_id || '')) throw new Error('Apply requires plan_id from preview.');
      return localLock(path.join(this.root, 'maintenance.lock'), async () => {
        const planFile = path.join(this.plans, plan_id + '.json');
        if ((await fs.lstat(planFile)).isSymbolicLink()) throw new Error('Unsafe cleanup plan.');
        const plan = await readJson(planFile);
        if (plan.target !== this.target || plan.scope !== 'local' || !Array.isArray(plan.items) || plan.items.length > 100 || plan.expires_at <= Date.now()) throw new Error('Cleanup plan expired or belongs to another server. Preview again.');
        if (plan.applied) throw new Error('Cleanup plan was already applied. Preview again.');
        await atomicJson(planFile, { ...plan, applied: true });
        const removed = [], skipped = [];
        for (const item of plan.items) {
          try {
            const current = await this.inspect(item.id);
            if (!current.eligible || current.fingerprint !== item.fingerprint) throw new Error('Changed transfer.');
            await this.downloads.cleanup(item.id, false, item.fingerprint);
            removed.push(item.id);
          } catch { skipped.push({ transfer_id: item.id, code: 'changed_or_unavailable' }); }
        }
        return { plan_id, removed, skipped };
      });
    }
    const cutoff = Date.parse(created_before || '');
    if (!Number.isFinite(cutoff) || cutoff > Date.now() || !Number.isInteger(max_items) || max_items < 1 || max_items > 100) throw new Error('Preview requires a past created_before and max_items=1..100.');
    await privateDirectory(this.plans);
    const { result, unavailable } = await this.entries();
    const candidates = result.filter(x => x.eligible && Number.isFinite(x.state.created_at) && x.state.created_at < cutoff).sort((a, b) => a.state.created_at - b.state.created_at || a.id.localeCompare(b.id));
    const items = candidates.slice(0, max_items).map(x => ({ id: x.id, fingerprint: x.fingerprint, bytes: x.bytes }));
    const id = crypto.randomBytes(16).toString('hex'), expires = Date.now() + 900000;
    await atomicJson(path.join(this.plans, id + '.json'), { target: this.target, scope: 'local', items, expires_at: expires });
    return { plan_id: id, preview: true, expires_at: new Date(expires).toISOString(), candidates: items.map(x => ({ transfer_id: x.id, bytes: x.bytes })), more: candidates.length > items.length, unavailable_count: unavailable };
  }
}
