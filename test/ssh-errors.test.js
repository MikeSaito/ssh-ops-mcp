import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import { once } from 'node:events';
import ssh2 from 'ssh2';
import { exec } from '../src/ssh.js';
import { rpc } from '../src/remote.js';
import { connectionError } from '../src/ssh-errors.js';

async function fixture(mode = 'success') {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = pair.privateKey.export({ type: 'pkcs1', format: 'pem' });
  const parsed = ssh2.utils.parseKey(key);
  const clients = new Set(), requests = [];
  const server = new ssh2.Server({ hostKeys: [key] }, client => {
    clients.add(client);
    client.on('close', () => clients.delete(client));
    client.on('error', () => {});
    client.on('authentication', ctx => ctx.method === 'password' && ctx.username === 'test-user' && ctx.password === 'synthetic-password' ? ctx.accept() : ctx.reject());
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('exec', (accept, reject, info) => {
        requests.push(info.command);
        const stream = accept();
        stream.on('error', () => {});
        stream.on('data', () => {});
        stream.on('end', () => {
          if (mode === 'disconnect') { client.end(); return; }
          if (mode === 'stall') return;
          stream.write(mode === 'null' ? 'null' : mode === 'invalid-json' ? 'not-json' : 'synthetic-output\n');
          if (mode !== 'missing-exit') stream.exit(0);
          stream.end();
        });
      });
    }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    requests,
    env: {
      SSH_HOST: '127.0.0.1', SSH_PORT: String(server.address().port),
      SSH_USERNAME: 'test-user', SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-password',
      SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + crypto.createHash('sha256').update(parsed.getPublicSSH()).digest('base64').replace(/=+$/, ''),
    },
    async close() { for (const client of clients) client.end(); await new Promise(resolve => server.close(resolve)); },
  };
}

test('connection classifications use safe static messages and never claim an earlier operation stopped', () => {
  for (const [input, code, phase] of [
    [{ level: 'client-timeout' }, 'ssh_connect_timeout', 'connect'],
    [{ level: 'client-authentication' }, 'ssh_authentication_failed', 'authentication'],
    [{ message: 'Host denied (verification failed)' }, 'ssh_host_key_rejected', 'host_verification'],
    [{ code: 'ECONNREFUSED' }, 'ssh_connection_refused', 'connect'],
    [{ code: 'ENOTFOUND' }, 'ssh_dns_failed', 'connect'],
    [{ code: 'EAI_AGAIN' }, 'ssh_dns_failed', 'connect'],
    [{ code: 'SSH_CLOSED_BEFORE_READY' }, 'ssh_connection_closed', 'connect'],
    [{}, 'ssh_connection_failed', 'connect'],
  ]) {
    const error = connectionError({ ...input, message: (input.message || '') + ' synthetic-credential' });
    assert.equal(error.code, code);
    assert.deepEqual(error.transport, { phase, dispatch_state: 'not_sent' });
    assert.ok(Object.isFrozen(error.transport));
    assert.ok(!error.message.includes('synthetic-credential'));
    assert.match(error.message, /Earlier operations may still be running/);
  }
});

test('successful SSH execution keeps stdout, stderr and exitCode unchanged', async () => {
  const f = await fixture();
  try {
    const result = await exec('synthetic-command', 2000, '', false, f.env);
    assert.equal(result.stdout, 'synthetic-output\n');
    assert.equal(result.stderr, '');
    assert.equal(result.exitCode, 0);
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});

test('refused connection is explicitly not sent, without automatic reconnect', async () => {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  await assert.rejects(exec('must-not-run', 1000, '', false, {
    SSH_HOST: '127.0.0.1', SSH_PORT: String(port), SSH_USERNAME: 'test-user',
    SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-password',
    SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, ''),
  }), error => {
    assert.equal(error.code, 'ssh_connection_refused');
    assert.deepEqual(error.transport, { phase: 'connect', dispatch_state: 'not_sent' });
    return true;
  });
});

for (const [mode, code] of [
  ['disconnect', 'ssh_connection_lost'],
  ['stall', 'ssh_command_timeout'],
  ['missing-exit', 'ssh_exit_status_missing'],
]) test(mode + ' keeps command outcome unknown and never sends a second command', async () => {
  const f = await fixture(mode);
  try {
    await assert.rejects(exec('synthetic-changing-command', 1000, '', false, f.env), error => {
      assert.equal(error.code, code);
      assert.deepEqual(error.transport, { phase: 'exec', dispatch_state: 'unknown' });
      assert.ok(!error.message.includes('synthetic-password'));
      return true;
    });
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});


for (const [override, code, phase] of [
  [{ SSH_PASSWORD: 'wrong-synthetic-password' }, 'ssh_authentication_failed', 'authentication'],
  [{ SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') }, 'ssh_host_key_rejected', 'host_verification'],
]) test(code + ' rejects before dispatch with no command received', async () => {
  const f = await fixture();
  try {
    await assert.rejects(exec('must-not-run', 1000, '', false, { ...f.env, ...override }), error => {
      assert.equal(error.code, code);
      assert.deepEqual(error.transport, { phase, dispatch_state: 'not_sent' });
      return true;
    });
    assert.equal(f.requests.length, 0);
  } finally { await f.close(); }
});

for (const mode of ['null', 'invalid-json']) test('invalid helper response (' + mode + ') retains an unknown outcome', async () => {
  const f = await fixture(mode);
  try {
    await assert.rejects(rpc('status', { operation_id: 'a'.repeat(32) }, 2000, f.env), error => {
      assert.equal(error.code, 'ssh_helper_invalid_response');
      assert.deepEqual(error.transport, { phase: 'response', dispatch_state: 'unknown' });
      return true;
    });
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});
