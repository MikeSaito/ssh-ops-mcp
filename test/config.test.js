import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { buildConnectOptions, connectionIdentity, stateDirectory } from '../src/config.js';
import { redact } from '../src/security.js';
import { makeKey } from './helpers.js';

const base = { SSH_HOST: 'example.invalid', SSH_USERNAME: 'deploy', SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-config-password', SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') };
test('secure defaults: explicit identity, method, port and pinned host key', async () => {
  const options = await buildConnectOptions(base);
  assert.equal(options.username, 'deploy'); assert.equal(options.port, 22);
  assert.equal(options.agentForward, false); assert.deepEqual(options.authHandler, ['password']);
  for (const name of ['SSH_HOST', 'SSH_USERNAME', 'SSH_AUTH_METHOD', 'SSH_HOST_FINGERPRINT_SHA256', 'SSH_PASSWORD']) {
    await assert.rejects(buildConnectOptions({ ...base, [name]: '' }));
  }
  for (const value of ['0', '-1', '65536', 'hello', '22.5']) await assert.rejects(buildConnectOptions({ ...base, SSH_PORT: value }));
  await assert.rejects(buildConnectOptions({ ...base, SSH_HOST: 'ssh://example.invalid' }));
  await assert.rejects(buildConnectOptions({ ...base, SSH_HOST_FINGERPRINT_SHA256: 'not-a-key' }));
  await assert.rejects(buildConnectOptions({ ...base, SSH_ALLOW_UNVERIFIED_HOST: 'yes' }));
  assert.equal((await buildConnectOptions({ ...base, SSH_HOST_FINGERPRINT_SHA256: '', SSH_ALLOW_UNVERIFIED_HOST: 'true' })).hostVerifier(Buffer.from('fake')), true);
});
test('credential files, encrypted keys and file-based secrets are validated and masked', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-config-'));
  try {
    const password = path.join(dir, 'password.txt'), key = path.join(dir, 'id_rsa');
    await fs.writeFile(password, 'synthetic-file-password\n', { mode: 0o600 });
    const env = { ...base, SSH_PASSWORD: '', SSH_PASSWORD_FILE: 'password.txt', SSH_MCP_CONFIG_DIR: dir };
    assert.equal((await buildConnectOptions(env)).password, 'synthetic-file-password');
    assert.equal(redact('result: synthetic-file-password'), 'result: [REDACTED]');
    await assert.rejects(buildConnectOptions({ ...env, SSH_PASSWORD: 'ambiguous' }));
    await fs.writeFile(key, makeKey('synthetic-passphrase').encoded, { mode: 0o600 });
    const keyEnv = { ...base, SSH_AUTH_METHOD: 'private_key', SSH_PRIVATE_KEY_PATH: key, SSH_KEY_PASSPHRASE: 'synthetic-passphrase' };
    assert.deepEqual((await buildConnectOptions(keyEnv)).authHandler, ['publickey']);
    await assert.rejects(buildConnectOptions({ ...keyEnv, SSH_KEY_PASSPHRASE: 'wrong' }), /Invalid private key/);
    await assert.rejects(buildConnectOptions({ ...keyEnv, SSH_PRIVATE_KEY_PATH: password }), /Invalid private key/);
    const linked = path.join(dir, 'linked-key');
    try {
      await fs.symlink(key, linked);
      await assert.rejects(buildConnectOptions({ ...keyEnv, SSH_PRIVATE_KEY_PATH: linked }), /regular file/);
    } catch (error) { if (error.code !== 'EPERM') throw error; }
    if (process.platform !== 'win32') {
      await fs.chmod(password, 0o644); await assert.rejects(buildConnectOptions(env), /0600/);
    }
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('agent socket is explicit or inherited, forwarding remains disabled', async () => {
  const env = { ...base, SSH_AUTH_METHOD: 'agent', SSH_AGENT_SOCKET: '/synthetic/agent.sock' };
  const options = await buildConnectOptions(env);
  assert.equal(options.agent, env.SSH_AGENT_SOCKET); assert.equal(options.agentForward, false);
  assert.deepEqual(options.authHandler, ['agent']); assert.equal(options.password, undefined);
  assert.equal((await buildConnectOptions({ ...env, SSH_AGENT_SOCKET: '', SSH_AUTH_SOCK: '/inherited.sock' })).agent, '/inherited.sock');
});
test('state isolation uses host, port and account, not secrets or working directory', () => {
  const env = { ...base, SSH_MCP_STATE_DIR: '/synthetic/state' };
  assert.equal(connectionIdentity(env), connectionIdentity({ ...env, SSH_PASSWORD: 'changed', SSH_PORT: '022', SSH_HOST: 'EXAMPLE.INVALID' }));
  for (const extra of [{ SSH_HOST: 'other.invalid' }, { SSH_PORT: '2222' }, { SSH_USERNAME: 'root' }]) assert.notEqual(stateDirectory(env), stateDirectory({ ...env, ...extra }));
  assert.equal(path.basename(stateDirectory(env)), connectionIdentity(env));
});
