import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import ssh2 from 'ssh2';
import { once } from 'node:events';
import { exec } from '../src/ssh.js';
import { connectionIdentity } from '../src/config.js';
import { operationId } from '../src/remote.js';
import { testServer, makeKey } from './helpers.js';

test('bastion verifies both hosts and never falls back to direct on denial', { timeout: 15000 }, async () => {
  const target = await testServer(), key = makeKey(), clients = new Set(), sockets = new Set();
  let forwards = 0, denied = false;
  const server = new ssh2.Server({ hostKeys: [key.plain] }, client => {
    clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client));
    client.on('authentication', ctx => ctx.method === 'password' && ctx.password === 'synthetic-jump' ? ctx.accept() : ctx.reject());
    client.on('ready', () => client.on('tcpip', (accept, reject, info) => {
      forwards++;
      if (denied || info.destIP !== '127.0.0.1' || info.destPort !== Number(target.env.SSH_PORT)) return reject();
      const socket = net.connect(info.destPort, info.destIP); sockets.add(socket);
      socket.on('close', () => sockets.delete(socket)); socket.on('error', () => reject());
      socket.once('connect', () => { const channel = accept(); channel.on('error', () => socket.destroy()); channel.on('close', () => socket.destroy()); socket.pipe(channel).pipe(socket); });
    }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const jump = { ...target.env, SSH_PORT: String(server.address().port), SSH_PASSWORD: 'synthetic-jump',
    SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + crypto.createHash('sha256').update(key.parsed.getPublicSSH()).digest('base64').replace(/=+$/, '') };
  try {
    const routed = { ...target.env, __jump: jump };
    assert.equal((await exec('synthetic', 5000, '', false, routed)).stdout, 'synthetic-output\n');
    assert.equal(forwards, 1); assert.notEqual(connectionIdentity(routed), connectionIdentity(target.env));
    assert.notEqual(operationId('same', routed), operationId('same', target.env));
    const badKey = 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, ''), attempts = target.attempts.length;
    await assert.rejects(exec('synthetic', 5000, '', false, { ...routed, __jump: { ...jump, SSH_HOST_FINGERPRINT_SHA256: badKey } }), /verification/);
    assert.equal(target.attempts.length, attempts);
    await assert.rejects(exec('synthetic', 5000, '', false, { ...routed, SSH_HOST_FINGERPRINT_SHA256: badKey }), /verification/);
    assert.equal(target.attempts.length, attempts);
    denied = true;
    await assert.rejects(exec('synthetic', 5000, '', false, routed), { code: 'ssh_transit_refused' });
    assert.equal(target.attempts.length, attempts);
  } finally { for (const client of clients) client.end(); for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await target.close(); }
});
