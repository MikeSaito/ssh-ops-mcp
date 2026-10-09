import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { once } from 'node:events';
import ssh2 from 'ssh2';
const { AgentProtocol } = ssh2;
import { connect } from '../src/ssh.js';
import { makeKey, testServer, disconnect } from './helpers.js';

test('password authenticates; wrong password and fingerprint fail without fallback', async () => {
  const server = await testServer();
  try {
    await disconnect(await connect(server.env));
    assert.ok(server.attempts.includes('password'));
    await assert.rejects(connect({ ...server.env, SSH_PASSWORD: 'wrong' }), /authentication/i);
    const count = server.attempts.length;
    await assert.rejects(connect({ ...server.env, SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') }), /verification/i);
    assert.equal(server.attempts.length, count, 'untrusted host never receives an auth attempt');
    assert.ok(!server.attempts.includes('publickey'));
  } finally { await server.close(); }
});
for (const encrypted of [false, true]) test(`${encrypted ? 'encrypted' : 'plain'} private key authenticates on a real local SSH connection`, async () => {
  const key = makeKey(encrypted ? 'synthetic-key-passphrase' : undefined);
  const server = await testServer(key), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-auth-'));
  try {
    const file = path.join(dir, 'id_rsa'); await fs.writeFile(file, key.encoded, { mode: 0o600 });
    await disconnect(await connect({ ...server.env, SSH_AUTH_METHOD: 'private_key', SSH_PRIVATE_KEY_PATH: file, ...(encrypted ? { SSH_KEY_PASSPHRASE: 'synthetic-key-passphrase' } : {}) }));
    assert.ok(server.attempts.includes('publickey')); assert.ok(!server.attempts.includes('password'));
  } finally { await server.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
test('SSH-agent signs through a real Unix socket or Windows named pipe', async () => {
  const key = makeKey(), server = await testServer(key);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-agent-'));
  const socketPath = process.platform === 'win32' ? '\\\\.\\pipe\\sshops-test-' + crypto.randomBytes(8).toString('hex') : path.join(dir, 'agent.sock');
  let signatures = 0;
  const sockets = new Set();
  const agent = net.createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    const protocol = new AgentProtocol(false); protocol.on('error', () => socket.destroy());
    protocol.on('identities', req => protocol.getIdentitiesReply(req, [key.parsed]));
    protocol.on('sign', (req, pubKey, data, flags) => {
      assert.deepEqual(pubKey.getPublicSSH(), key.parsed.getPublicSSH());
      signatures++; protocol.signReply(req, key.parsed.sign(data, flags.hash));
    });
    socket.pipe(protocol).pipe(socket);
  });
  try {
    agent.listen(socketPath); await once(agent, 'listening');
    await disconnect(await connect({ ...server.env, SSH_AUTH_METHOD: 'agent', SSH_AGENT_SOCKET: socketPath }));
    assert.ok(signatures > 0); assert.ok(server.attempts.includes('publickey')); assert.ok(!server.attempts.includes('password'));
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => agent.close(resolve));
    await server.close(); await fs.rm(dir, { recursive: true, force: true });
  }
});
