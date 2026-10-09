import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { transferPath } from './security.js';
import { atomicJson, readJson, localLock, privateDirectory, alive, delay, openKey, fileIdentity } from './local-state.js';
import { scanPartial } from './encrypted-file.js';

export class Downloads {
  constructor(stateDir) { this.root = stateDir; this.base = path.join(stateDir, 'downloads'); }
  directory(id) {
    if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('Invalid transfer_id.');
    return path.join(this.base, id);
  }
  async status(id) {
    const dir = this.directory(id);
    const data = await readJson(path.join(dir, 'status.json'));
    if (['starting', 'running', 'verifying', 'publishing'].includes(data.state) && !alive(data.worker_pid)) data.state = 'interrupted';
    // Never return remote contents, stored key blobs or credentials.
    return { transfer_id: id, state: data.state, bytes_downloaded: data.bytes_downloaded || 0,
      total_bytes: data.total_bytes ?? null, percent: data.total_bytes ? Math.min(100, Math.floor(100 * (data.bytes_downloaded || 0) / data.total_bytes)) : (data.state === 'completed' ? 100 : 0),
      encrypted: data.encrypt, sha256: data.sha256, path: data.state === 'completed' ? data.destination : undefined,
      expires_at: data.expires_at, detail: data.detail };
  }
  async start(args) {
    await privateDirectory(this.base);
    await privateDirectory(path.join(this.root, 'transfers'));
    const id = crypto.randomBytes(16).toString('hex');
    const dir = this.directory(id); await privateDirectory(dir);
    const local = args.encrypt && !args.local_path.endsWith('.mcpenc') ? args.local_path + '.mcpenc' : args.local_path;
    const destination = await transferPath(this.root, local, true);
    await privateDirectory(path.dirname(destination));
    if (!args.overwrite && await fs.lstat(destination).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; })) throw new Error('Destination already exists.');
    const retention = args.retention_days ?? 7;
    await atomicJson(path.join(dir, 'status.json'), { transfer_id: id, state: 'interrupted', remote_path: args.remote_path,
      destination, local_path: local, overwrite: args.overwrite ?? false, encrypt: args.encrypt ?? false,
      created_at: Date.now(), expires_at: new Date(Date.now() + retention * 86400000).toISOString(), bytes_downloaded: 0 });
    await this.resume(id);
    return this.status(id);
  }
  async resume(id) {
    const dir = this.directory(id);
    return localLock(path.join(dir, 'control.lock'), async () => {
      const state = await readJson(path.join(dir, 'status.json'));
      if (state.state === 'completed' || ['starting', 'running', 'verifying', 'publishing'].includes(state.state) && alive(state.worker_pid)) return this.status(id);
      if (['source_changed', 'integrity_failed', 'expired'].includes(state.state)) throw new Error('Transfer cannot be resumed: ' + state.state + '. Start an intentionally new transfer.');
      if (Date.parse(state.expires_at) <= Date.now()) throw new Error('Transfer retention expired; use ssh_download_cleanup.');
      await fs.unlink(path.join(dir, 'pause')).catch(() => {});
      state.state = 'starting'; state.detail = undefined;
      // Claim the worker PID before launching I/O; concurrent resumes are serialized.
      const child = spawn(process.execPath, [fileURLToPath(new URL('./download-worker.js', import.meta.url)), this.root, id],
        { detached: true, windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], env: process.env });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { child.kill(); reject(new Error('Download worker did not become ready.')); }, 15000);
        child.once('message', message => { clearTimeout(timer); message.ready ? resolve() : reject(new Error('Invalid worker handshake.')); });
        child.once('error', error => { clearTimeout(timer); reject(error); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error('Download worker exited before becoming ready.')); });
      });
      state.worker_pid = child.pid;
      await atomicJson(path.join(dir, 'status.json'), state);
      child.send({ run: true }); child.disconnect(); child.unref();
      return this.status(id);
    });
  }
  async pause(id) {
    const dir = this.directory(id);
    await fs.writeFile(path.join(dir, 'pause'), '', { mode: 0o600 });
    return { ...await this.status(id), pause_requested: true };
  }
  async wait(id, milliseconds) {
    const deadline = Date.now() + milliseconds;
    let result;
    do {
      result = await this.status(id);
      if (!['starting', 'running', 'verifying', 'publishing'].includes(result.state)) return result;
      await delay(150);
    } while (Date.now() < deadline);
    return result;
  }
  async list() {
    await fs.mkdir(this.base, { recursive: true, mode: 0o700 });
    const entries = await fs.readdir(this.base);
    const result = [];
    for (const id of entries.filter(id => /^[a-f0-9]{32}$/.test(id)).slice(-100)) result.push(await this.status(id));
    return { transfers: result };
  }
  async cleanupExpired() {
    const entries = await fs.readdir(this.base).catch(error => { if (error.code === 'ENOENT') return []; throw error; });
    let removed = 0;
    for (const id of entries.filter(id => /^[a-f0-9]{32}$/.test(id))) {
      const state = await readJson(path.join(this.directory(id), 'status.json')).catch(() => null);
      if (!state || state.state === 'expired' || Date.parse(state.expires_at) > Date.now()) continue;
      if (alive(state.worker_pid) && ['starting', 'running', 'verifying', 'publishing'].includes(state.state)) continue;
      try { await this.cleanup(id); removed++; } catch { /* Refuse unsafe deletion; leave status for inspection. */ }
    }
    return { expired_transfers_removed: removed };
  }
  async cleanup(id, expiredOnly = true) {
    const dir = this.directory(id);
    return localLock(path.join(dir, 'control.lock'), async () => {
      const state = await readJson(path.join(dir, 'status.json'));
      if (alive(state.worker_pid) && ['starting', 'running', 'verifying', 'publishing'].includes(state.state)) throw new Error('Pause and wait for the worker before cleanup.');
      if (expiredOnly && Date.parse(state.expires_at) > Date.now()) throw new Error('Retention has not expired; expired_only=false is an explicit deletion request.');
      if (state.state === 'completed') {
        const target = await transferPath(this.root, state.local_path);
        if (target !== state.destination) throw new Error('Invalid saved destination.');
        if (await fileIdentity(target).catch(error => { if (error.code === 'ENOENT') return null; throw error; }) !== state.destination_identity)
          throw new Error('Completed target was replaced/changed; cleanup refuses to delete another version.');
        await fs.unlink(target).catch(error => { if (error.code !== 'ENOENT') throw error; });
      }
      // Only the known files of this exact transfer, never recursive workspace deletion.
      for (const name of ['data.part', 'key.json', 'pause']) await fs.unlink(path.join(dir, name)).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await atomicJson(path.join(dir, 'status.json'), { ...state, state: 'expired', worker_pid: null, detail: 'Downloaded data and encryption key removed.' });
      return this.status(id);
    });
  }
  async decrypt(id, localPath) {
    const dir = this.directory(id);
    return localLock(path.join(dir, 'control.lock'), async () => {
      const state = await readJson(path.join(dir, 'status.json'));
      if (state.state !== 'completed' || !state.encrypt) throw new Error('An encrypted completed transfer is required.');
      if (Date.parse(state.expires_at) <= Date.now()) throw new Error('Encrypted transfer retention expired.');
      const source = await transferPath(this.root, state.local_path);
      if (await fileIdentity(source) !== state.destination_identity) throw new Error('Encrypted source was replaced/changed.');
      const destination = await transferPath(this.root, localPath, true);
      await privateDirectory(path.dirname(destination));
      const temp = path.join(dir, 'decrypt-' + crypto.randomBytes(8).toString('hex') + '.part');
      const key = await openKey(await readJson(path.join(dir, 'key.json')));
      const input = await fs.open(source, 'r'), output = await fs.open(temp, 'wx', 0o600);
      try {
        const result = await scanPartial(input, key, id, async bytes => {
          let written = 0;
          while (written < bytes.length) written += (await output.write(bytes, written, bytes.length - written)).bytesWritten;
        });
        if (!result.complete || result.position !== state.total_bytes || result.hash.digest('hex') !== state.sha256) throw new Error('Encrypted download integrity check failed.');
        await output.sync(); await output.close();
        await fs.link(temp, destination);
        return { transfer_id: id, path: destination, encrypted: false, sha256: state.sha256,
          warning: 'Explicit plaintext export, protected by private directory ACL. Delete it when no longer needed; transfer cleanup does not remove exports.' };
      } finally { await input.close(); await output.close().catch(() => {}); await fs.unlink(temp).catch(() => {}); key.fill(0); }
    });
  }
}
