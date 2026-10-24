import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import ssh2 from 'ssh2';
import { rpc } from '../src/remote.js';
import { withSftp } from '../src/ssh.js';
import { makeKey } from './helpers.js';

// Only the fixture injects faults. The production helper has no fault/debug API.
const faultSource = fault => fault === 'disk_full' ? `
import os,errno
_original_sync=os.fsync
def _test_sync(fd):
    if '.mcp-stage-' in os.readlink('/proc/self/fd/%d'%fd):
        raise OSError(errno.ENOSPC,'Synthetic full disk')
    return _original_sync(fd)
os.fsync=_test_sync
` : fault ? `
import os
_original_replace=os.replace
def _test_replace(source,destination):
    if '.mcp-stage-' in str(source):
        ${fault === 'after_replace' ? '_original_replace(source,destination)' : 'pass'}
        os._exit(91)
    return _original_replace(source,destination)
os.replace=_test_replace
` : '';

async function linuxServer() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-real-files-'));
  const uid = process.getuid() === 0 ? 65534 : process.getuid(), gid = process.getuid() === 0 ? 65534 : process.getgid();
  await fs.chown(root, uid, gid);
  const host = makeKey(), clients = new Set(), children = new Set();
  let fault;
  const server = new ssh2.Server({ hostKeys: [host.plain] }, client => {
    clients.add(client); client.on('close', () => clients.delete(client)); client.on('error', () => {});
    client.on('authentication', ctx => ctx.username === 'synthetic' && ctx.method === 'password' && ctx.password === 'synthetic-only' ? ctx.accept() : ctx.reject());
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('exec', (accept, reject, info) => {
        if (!info.command.startsWith('python3 -c ')) return reject();
        const stream = accept(); let input = '';
        stream.on('data', bytes => { input += bytes; });
        stream.on('end', () => {
          const payload = JSON.parse(input); payload.source = faultSource(fault) + payload.source;
          const child = spawn('/bin/sh', ['-c', info.command], { cwd: root, uid, gid,
            env: { PATH: process.env.PATH, HOME: root, TMPDIR: root, LANG: 'C.UTF-8' } });
          children.add(child); child.on('error', () => {}); child.stdin.on('error', () => {});
          child.stdout.pipe(stream, { end: false }); child.stderr.pipe(stream.stderr, { end: false });
          child.on('close', code => { children.delete(child); if (!stream.destroyed) { stream.exit(code ?? 1); stream.end(); } });
          child.stdin.end(JSON.stringify(payload));
        });
      });
      session.on('sftp', accept => {
        const sftp = accept(), handles = new Map(); let next = 0;
        const code = ssh2.utils.sftp.STATUS_CODE;
        sftp.on('error', () => {});
        sftp.on('OPEN', async (request, filename, flags, attrs) => {
          try {
            if (!path.resolve(filename).startsWith(root + path.sep)) throw new Error('Outside fixture');
            const file = await fs.open(filename, 'w', attrs.mode ?? 0o600), id = String(++next);
            handles.set(id, file); sftp.handle(request, Buffer.from(id));
          } catch { sftp.status(request, code.FAILURE); }
        });
        sftp.on('WRITE', async (request, handle, offset, data) => {
          try { const file = handles.get(handle.toString()); let written = 0; while (written < data.length) written += (await file.write(data, written, data.length - written, offset + written)).bytesWritten; sftp.status(request, code.OK); }
          catch { sftp.status(request, code.FAILURE); }
        });
        sftp.on('CLOSE', async (request, handle) => {
          try { await handles.get(handle.toString()).close(); handles.delete(handle.toString()); sftp.status(request, code.OK); }
          catch { sftp.status(request, code.FAILURE); }
        });
        sftp.on('close', () => { for (const file of handles.values()) file.close().catch(() => {}); });
      });
    }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const env = { SSH_HOST: '127.0.0.1', SSH_PORT: String(server.address().port), SSH_USERNAME: 'synthetic', SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-only',
    SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + crypto.createHash('sha256').update(host.parsed.getPublicSSH()).digest('base64').replace(/=+$/, '') };
  return { root, uid, gid, env, setFault(value) { fault = value; }, async close() {
    for (const client of clients) client.end();
    await new Promise(resolve => server.close(resolve));
    await Promise.all([...children].map(child => once(child, 'close')));
    await fs.rm(root, { recursive: true, force: true });
  } };
}

test('real Linux SSH executes Python writes, validation, backups, SFTP commits and failure recovery', { skip: process.platform !== 'linux', timeout: 60000 }, async () => {
  const server = await linuxServer();
  const call = (action, args) => rpc(action, args, 10000, server.env);
  const file = path.join(server.root, 'config.txt');
  const hash = async () => (await call('file_hash', { path: file })).sha256;
  try {
    const created = await call('write', { path: file, content: 'generation one', expected_sha256: null, mode: '0640' });
    assert.equal((await fs.stat(file)).mode & 0o777, 0o640);
    const updated = await call('write', { path: file, content: 'generation two', expected_sha256: created.sha256 });
    assert.equal(await fs.readFile(updated.backup, 'utf8'), 'generation one');
    assert.equal((await fs.stat(updated.backup)).mode & 0o777, 0o600);
    assert.equal((await fs.stat(file)).uid, server.uid); assert.equal((await fs.stat(file)).gid, server.gid);
    await assert.rejects(call('write', { path: file, content: 'invalid', expected_sha256: updated.sha256, validate_command: 'test -f {path} && false' }), /validation failed/);
    assert.equal(await hash(), updated.sha256);
    await assert.rejects(call('write', { path: file, content: 'stale', expected_sha256: created.sha256 }), /changed/);
    const link = path.join(server.root, 'symlink'); await fs.symlink(file, link);
    await assert.rejects(call('write', { path: link, content: 'unsafe', expected_sha256: updated.sha256 }), /symlink/);
    const denied = path.join(server.root, 'denied'); await fs.mkdir(denied); await fs.chown(denied, server.uid, server.gid); await fs.chmod(denied, 0o500);
    await assert.rejects(call('write', { path: path.join(denied, 'new'), content: 'no', expected_sha256: null }), /Permission denied/);
    server.setFault('disk_full');
    await assert.rejects(call('write', { path: file, content: 'full', expected_sha256: updated.sha256 }), /full disk/);
    server.setFault(); assert.equal(await hash(), updated.sha256);
    server.setFault('before_replace');
    await assert.rejects(call('write', { path: file, content: 'before crash', expected_sha256: updated.sha256 }), { code: 'ssh_helper_failed' });
    server.setFault(); assert.equal(await hash(), updated.sha256);
    server.setFault('after_replace');
    await assert.rejects(call('write', { path: file, content: 'after crash', expected_sha256: updated.sha256 }), { code: 'ssh_helper_failed' });
    server.setFault(); assert.equal(await fs.readFile(file, 'utf8'), 'after crash');
    const upload_id = 'b'.repeat(32), prepared = await call('upload_prepare', { upload_id });
    const bytes = crypto.randomBytes(128 * 1024);
    await withSftp(sftp => new Promise((resolve, reject) => sftp.writeFile(prepared.path, bytes, error => error ? reject(error) : resolve())), 10000, server.env);
    const committed = await call('upload_commit', { upload_id, path: file, expected_sha256: await hash() });
    assert.equal(committed.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
    assert.deepEqual(await fs.readFile(file), bytes); assert.equal((await fs.stat(file)).mode & 0o777, 0o640);
  } finally { await server.close(); }
});
