import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { withSftp } from './ssh.js';
import { rpc } from './remote.js';
import { atomicJson, readJson, localLock, openKey, sealKey, fileIdentity } from './local-state.js';
import { transferPath } from './security.js';
import { encryptFrame, scanPartial, MAGIC } from './encrypted-file.js';

const [, , root, id] = process.argv;
if (!/^[a-f0-9]{32}$/.test(id || '')) throw new Error('Invalid transfer ID.');
const dir = path.join(root, 'downloads', id);
const statusFile = path.join(dir, 'status.json');
const part = path.join(dir, 'data.part');
let state, file;
const invoke = (sftp, name, ...args) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('SFTP read stalled.')), 30000);
  sftp[name](...args, (error, value) => { clearTimeout(timer); error ? reject(error) : resolve(value); });
});
const save = () => atomicJson(statusFile, state);
async function paused() { return fs.stat(path.join(dir, 'pause')).then(() => true, () => false); }
function unchanged(before, after) { return ['size', 'mtime_ns', 'ctime_ns', 'inode', 'device', 'sha256'].every(name => before[name] === after[name]); }
async function run() {
  state = await readJson(statusFile);
  try {
    // Recover a crash after atomic publication but before the completion manifest.
    if (state.publication_identity && await fileIdentity(state.destination).catch(() => null) === state.publication_identity) {
      const key = state.encrypt ? await openKey(await readJson(path.join(dir, 'key.json'))) : null;
      const published = await fs.open(state.destination, 'r');
      try {
        const verified = await scanPartial(published, key, id);
        if (!verified.complete || verified.position !== state.total_bytes || verified.hash.digest('hex') !== state.sha256) {
          state.state = 'integrity_failed'; throw new Error('integrity_failed');
        }
      } finally { await published.close(); if (key) key.fill(0); }
      await fs.unlink(part).catch(() => {});
      state.state = 'completed'; state.destination_identity = state.publication_identity; state.finished_at = Date.now();
      return;
    }
    state.state = 'running'; state.updated_at = Date.now(); await save();
    const snapshot = await rpc('file_snapshot', { path: state.remote_path }, 1800000);
    if (state.source && !unchanged(state.source, snapshot)) { state.state = 'source_changed'; throw new Error('source_changed'); }
    state.source = snapshot; state.total_bytes = snapshot.size; await save();
    let key = null;
    if (state.encrypt) {
      const keyFile = path.join(dir, 'key.json');
      let sealed = await readJson(keyFile).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
      if (!sealed) { sealed = await sealKey(crypto.randomBytes(32)); await atomicJson(keyFile, sealed); }
      key = await openKey(sealed);
    }
    file = await fs.open(part, 'a+', 0o600);
    if (key && (await file.stat()).size === 0) { await file.write(MAGIC); await file.sync(); }
    const prior = await scanPartial(file, key, id);
    if (!prior.complete) await file.truncate(prior.fileOffset);
    const hash = prior.hash;
    let position = prior.position;
    if (position > snapshot.size) { state.state = 'integrity_failed'; throw new Error('integrity_failed'); }
    state.bytes_downloaded = position; await save();
    let lastSave = Date.now();
    await withSftp(async sftp => {
      const remote = await invoke(sftp, 'open', state.remote_path, 'r');
      try {
        const before = await invoke(sftp, 'fstat', remote);
        if (before.size !== snapshot.size || before.mtime !== Math.floor(Number(snapshot.mtime_ns) / 1e9)) { state.state = 'source_changed'; throw new Error('source_changed'); }
        // Pipeline several requests per megabyte while committing strictly in order.
        const batchSize = 1024 * 1024, chunkSize = 65536;
        while (position < snapshot.size) {
          if (await paused()) { state.state = 'paused'; return; }
          const size = Math.min(batchSize, snapshot.size - position);
          const batch = Buffer.alloc(size);
          const reads = [];
          for (let offset = 0; offset < size; offset += chunkSize) {
            const length = Math.min(chunkSize, size - offset);
            reads.push(new Promise((resolve, reject) => {
              const timer = setTimeout(() => reject(new Error('SFTP read stalled.')), 30000);
              sftp.read(remote, batch, offset, length, position + offset, (error, count) => {
                clearTimeout(timer); error ? reject(error) : count !== length ? reject(new Error('Remote file shortened.')) : resolve();
              });
            }));
          }
          await Promise.all(reads);
          const bytes = key ? encryptFrame(key, id, position, batch) : batch;
          let written = 0;
          while (written < bytes.length) written += (await file.write(bytes, written, bytes.length - written)).bytesWritten;
          hash.update(batch); position += batch.length; state.bytes_downloaded = position;
          if (Date.now() - lastSave >= 250) { await file.sync(); state.updated_at = Date.now(); await save(); lastSave = Date.now(); }
        }
        const after = await invoke(sftp, 'fstat', remote);
        if (after.size !== before.size || after.mtime !== before.mtime) { state.state = 'source_changed'; throw new Error('source_changed'); }
      } finally { await invoke(sftp, 'close', remote).catch(() => {}); }
    }, 86400000);
    await file.sync();
    if (state.state === 'paused') return;
    state.state = 'verifying'; await save();
    const actual = hash.digest('hex');
    const final = await rpc('file_snapshot', { path: state.remote_path }, 1800000);
    if (!unchanged(snapshot, final)) { state.state = 'source_changed'; throw new Error('source_changed'); }
    if (actual !== snapshot.sha256) { state.state = 'integrity_failed'; throw new Error('integrity_failed'); }
    await file.close(); file = null;
    const destination = await transferPath(root, state.local_path);
    await localLock(path.join(root, 'downloads', 'destination-' + crypto.createHash('sha256').update(destination).digest('hex') + '.lock'), async () => {
      state.state = 'publishing'; state.sha256 = actual; state.publication_identity = await fileIdentity(part); await save();
      if (state.overwrite) await fs.rename(part, destination);
      else { await fs.link(part, destination); await fs.unlink(part); }
      state.destination_identity = await fileIdentity(destination);
    });
    state.state = 'completed'; state.sha256 = actual; state.finished_at = Date.now();
  } catch (error) {
    if (!['source_changed', 'integrity_failed'].includes(state.state)) state.state = 'interrupted';
    state.detail = ['source_changed', 'integrity_failed'].includes(state.state) ? state.state : 'Download interrupted; inspect status and resume the same transfer_id. No automatic restart.';
  } finally {
    if (file) await file.close().catch(() => {});
    state.worker_pid = null; state.updated_at = Date.now(); await save();
  }
}
// Parent persists the PID and metadata before allowing remote I/O.
const launchTimer = setTimeout(() => process.exit(1), 10000);
process.once('message', async () => {
  clearTimeout(launchTimer);
  await localLock(path.join(dir, 'worker.lock'), run).catch(() => {});
  process.exit(0);
});
process.send({ ready: true });
