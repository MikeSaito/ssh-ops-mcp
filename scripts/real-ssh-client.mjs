import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import ssh2 from 'ssh2';
import { exec, withSftp } from '../src/ssh.js';
import { rpc, operationId } from '../src/remote.js';
import { Downloads } from '../src/downloads.js';
import { privateDirectory } from '../src/local-state.js';

const { open, drop, alpine, noSftp, privateTarget } = JSON.parse(process.env.SSHOPS_FIXTURES);
const dir = '/tmp/keys', checks = [];
async function until(fn, timeout = 20000) {
  const deadline = Date.now() + timeout;
  do { if (await fn()) return; await new Promise(resolve => setTimeout(resolve, 200)); } while (Date.now() < deadline);
  throw new Error('Synthetic daemon operation timed out.');
}
async function check(name, fn) { await fn(); checks.push(name); console.log('PASS ' + name); }
  for (const server of [open, drop, alpine]) {
    await check(server.name.split('-')[1] + ': command, file edit, search, SFTP and durable operation', async () => {
      assert.equal((await exec('printf synthetic-output; printf synthetic-error >&2; exit 7', 5000, '', false, server.env)).exitCode, 7);
      const file = '/home/synthetic/config.txt';
      const created = await rpc('write', { path: file, content: 'alpha\r\nbeta\r\n', expected_sha256: null, mode: '0640' }, 10000, server.env);
      const edited = await rpc('write', { path: file, expected_sha256: created.sha256, edits: [{ old_text: 'beta', new_text: 'gamma' }] }, 10000, server.env);
      assert.equal((await rpc('read', { path: file }, 10000, server.env)).text, 'alpha\r\ngamma\r\n');
      assert.ok(edited.backup);
      await assert.rejects(rpc('write', { path: file, content: 'stale', expected_sha256: created.sha256 }, 10000, server.env), /changed/);
      assert.equal((await rpc('search', { path: '/home/synthetic', text: 'gamma', pattern: '*.txt' }, 10000, server.env)).results.length, 1);
      const bytes = crypto.randomBytes(131072), remote = '/home/synthetic/binary';
      await withSftp(sftp => new Promise((resolve, reject) => sftp.writeFile(remote, bytes, error => error ? reject(error) : resolve())), 10000, server.env);
      const got = await withSftp(sftp => new Promise((resolve, reject) => sftp.readFile(remote, (error, data) => error ? reject(error) : resolve(data))), 10000, server.env);
      assert.deepEqual(got, bytes);
      const id = operationId('daemon-test', server.env);
      const spec = { operation_id: id, command: 'sleep 1; printf durable', timeout_seconds: 10, request_id: 'daemon-test', resource: '/synthetic-test' };
      await rpc('start', spec, 10000, server.env);
      assert.equal((await rpc('start', spec, 10000, server.env)).reused, true);
      await until(async () => (await rpc('status', { operation_id: id }, 10000, server.env)).state === 'completed');
      assert.equal((await rpc('logs', { operation_id: id, stream: 'stdout' }, 10000, server.env)).text, 'durable');
      const cancelId = operationId('daemon-cancel', server.env);
      await rpc('start', { ...spec, operation_id: cancelId, command: 'sleep 30', request_id: 'daemon-cancel' }, 10000, server.env);
      await rpc('cancel', { operation_id: cancelId }, 10000, server.env);
      await until(async () => ['cancelled', 'failed'].includes((await rpc('status', { operation_id: cancelId }, 10000, server.env)).state));
    });
    for (const locked of [false, true]) await check(server.name.split('-')[1] + ': ' + (locked ? 'encrypted' : 'plain') + ' key', async () => {
      const file = path.join(dir, server.name + (locked ? '-locked' : '-plain'));
      await fs.chmod(file, 0o600);
      const env = { ...server.env, SSH_AUTH_METHOD: 'private_key', SSH_PRIVATE_KEY_PATH: file, ...(locked ? { SSH_KEY_PASSPHRASE: 'synthetic-fixture-passphrase' } : {}) };
      assert.equal((await exec('true', 5000, '', false, env)).exitCode, 0);
    });
    await check(server.name.split('-')[1] + ': untrusted host and wrong password rejected', async () => {
      await assert.rejects(exec('true', 5000, '', false, { ...server.env, SSH_PASSWORD: 'synthetic-wrong' }), /authentication/i);
      await assert.rejects(exec('true', 5000, '', false, { ...server.env, SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') }), /verification/);
    });
    await check(server.name.split('-')[1] + ': agent authentication without forwarding', async () => {
      const key = ssh2.utils.parseKey(await fs.readFile(path.join(dir, server.name + '-plain')));
      const socket = '/tmp/sshops-agent-' + crypto.randomBytes(6).toString('hex'), clients = new Set();
      const agent = net.createServer(stream => {
        clients.add(stream); stream.on('close', () => clients.delete(stream)); stream.on('error', () => {});
        const protocol = new ssh2.AgentProtocol(false); protocol.on('error', () => stream.destroy());
        protocol.on('identities', request => protocol.getIdentitiesReply(request, [key]));
        protocol.on('sign', (request, publicKey, data, options) => {
          if (!publicKey.getPublicSSH().equals(key.getPublicSSH())) return protocol.failureReply(request);
          const signature = key.sign(data, options.hash);
          if (signature instanceof Error) protocol.failureReply(request); else protocol.signReply(request, signature);
        });
        stream.pipe(protocol).pipe(stream);
      });
      agent.listen(socket); await once(agent, 'listening');
      try {
        const result = await exec('test -z "$SSH_AUTH_SOCK" && printf agent-ok', 5000, '', false,
          { ...server.env, SSH_AUTH_METHOD: 'agent', SSH_AGENT_SOCKET: socket });
        assert.equal(result.exitCode, 0); assert.equal(result.stdout, 'agent-ok');
      } finally { for (const client of clients) client.destroy(); await new Promise(resolve => agent.close(resolve)); }
    });
  }
  await check('missing SFTP fails without fallback', async () => {
    await assert.rejects(withSftp(async () => {}, 5000, noSftp.env), error => error.code?.startsWith('ssh_sftp'));
  });
  await check('real bastion, independent target key, no direct fallback', async () => {
    const routed = { ...privateTarget.env, SSH_HOST: 'private.fixture.invalid', SSH_PORT: '22', __jump: open.env };
    assert.equal((await exec('hostname', 5000, '', false, routed)).stdout.trim(), 'private-fixture');
    assert.equal((await rpc('file_hash', { path: '/home/synthetic/.ssh/authorized_keys' }, 10000, routed)).exists, true);
    await assert.rejects(exec('true', 5000, '', false, privateTarget.env));
    await assert.rejects(exec('true', 5000, '', false, { ...routed, SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') }), /verification/);
  });
  await check('download worker retains its bastion route and rejects another route', async () => {
    const env = { ...privateTarget.env, __jump: open.env };
    const state = '/tmp/sshops-route-download-' + crypto.randomBytes(6).toString('hex');
    await privateDirectory(state);
    const downloads = new Downloads(state, env, true);
    let id;
    try {
      await exec("printf synthetic-routed-file > /home/synthetic/routed.txt", 5000, '', false, env);
      id = (await downloads.start({ remote_path: '/home/synthetic/routed.txt', local_path: 'transfers/routed.txt' })).transfer_id;
      const completed = await downloads.wait(id, 20000);
      assert.equal(completed.state, 'completed', JSON.stringify(completed));
      assert.equal(await fs.readFile(completed.path, 'utf8'), 'synthetic-routed-file');
      await assert.rejects(new Downloads(state, privateTarget.env, true).resume(id), /does not belong/);
      const restarted = new Downloads(state, env, true);
      assert.equal((await restarted.resume(id)).state, 'completed');
    } finally {
      if (id) { await downloads.pause(id); await downloads.wait(id, 20000); }
      await fs.rm(state, { recursive: true, force: true });
    }
  });

if (process.argv.includes('--bench')) {
  const { benchmark } = await import('./ssh-benchmark.mjs');
  console.log(JSON.stringify({ benchmarks: [await benchmark(open.env, 'OpenSSH'), await benchmark(drop.env, 'Dropbear')] }));
}
console.log(JSON.stringify({ real_daemons: true, passed: checks.length, production_connections: 0 }));
