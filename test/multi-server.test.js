import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { loadRegistry, workerEnvironment, snapshotEnvironment, buildConnectOptions } from '../src/config.js';
import { operationId } from '../src/remote.js';
import { redact } from '../src/security.js';
import { syntheticServer } from './multi-server-helper.js';

const root = path.resolve(import.meta.dirname, '..');
const publicCopy = await fs.access(path.join(root, 'bin', 'ssh-ops-mcp.js')).then(() => true, () => false);
const entry = publicCopy ? path.join(root, 'bin', 'ssh-ops-mcp.js') : path.join(root, 'src', 'index.js');
const cleanEnv = () => Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('SSH_')));
const writeEnv = (file, env) => fs.writeFile(file, Object.entries(env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn) { const deadline = Date.now() + 20000; do { const result = await fn(); if (result) return result; await wait(75); } while (Date.now() < deadline); throw new Error('Synthetic test timed out'); }

async function fixture() {
  const first = await syntheticServer('alpha', 'synthetic-alpha-password', Buffer.alloc(8 * 1024 * 1024, 65), 90);
  const second = await syntheticServer('beta', 'synthetic-beta-password', Buffer.from('beta-dump'));
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-multi-'));
  const serversFile = path.join(dir, 'servers.json');
  const config = { version: 1, servers: [{ id: 'alpha', name: 'Alpha', env_file: 'alpha.env' }, { id: 'beta', env_file: 'beta.env' }] };
  await writeEnv(path.join(dir, 'alpha.env'), first.env); await writeEnv(path.join(dir, 'beta.env'), second.env);
  await fs.writeFile(serversFile, JSON.stringify(config), { mode: 0o600 });
  const env = { ...cleanEnv(), SSH_MCP_STATE_DIR: path.join(dir, 'state'), SSH_HOST: 'wrong.invalid', SSH_PASSWORD: 'wrong-inherited-password' };
  return { first, second, dir, config, serversFile, env,
    async open() {
      const client = new Client({ name: 'multi-test', version: '1' });
      const args = publicCopy ? [entry, '--servers-file', serversFile] : [entry];
      const transport = new StdioClientTransport({ command: process.execPath, args, env: { ...env, ...(publicCopy ? {} : { SSH_MCP_SERVERS_FILE: serversFile }) }, cwd: os.tmpdir(), stderr: 'pipe' });
      let stderr = ''; transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
      await client.connect(transport);
      return { client, async call(name, args = {}) { return client.callTool({ name, arguments: args }); },
        async value(name, args = {}) { const response = await client.callTool({ name, arguments: args }); assert.ok(!response.isError, JSON.stringify(response)); assert.equal(response.structuredContent, undefined); return JSON.parse(response.content[0].text); },
        errors: () => stderr, async close() { await client.close(); await transport.close(); } };
    },
    async close() { await first.close(); await second.close(); await fs.rm(dir, { recursive: true, force: true }); },
  };
}

test('registry validates private profiles locally, resolves relative paths and rejects ambiguity', async () => {
  const f = await fixture();
  try {
    const registry = await loadRegistry({ serversFile: f.serversFile, env: f.env });
    assert.equal(registry.profiles.size, 2); assert.equal(f.first.attempts.length + f.second.attempts.length, 0);
    const a = registry.profiles.get('alpha'), b = registry.profiles.get('beta');
    assert.notEqual(a.stateDir, b.stateDir); assert.equal(a.env.SSH_PASSWORD, f.first.env.SSH_PASSWORD);
    assert.equal(a.env.SSH_MCP_CONFIG_DIR, f.dir); assert.equal(Object.isFrozen(a.env), true);
    assert.notEqual(operationId('same-request', a.env), operationId('same-request', b.env));
    for (const cfg of [
      { version: 2, servers: f.config.servers }, { version: 1, servers: [] },
      { version: 1, servers: [f.config.servers[0], f.config.servers[0]] },
      { version: 1, servers: [{ id: 'alpha', env_file: 'alpha.env' }, { id: 'alias', env_file: 'alpha.env' }] },
      { version: 1, servers: [{ id: '../escape', env_file: 'alpha.env' }] },
      { version: 1, servers: [{ id: 'alpha', env_file: 'missing.env' }] },
    ]) {
      await fs.writeFile(f.serversFile, JSON.stringify(cfg)); await assert.rejects(loadRegistry({ serversFile: f.serversFile, env: f.env }));
    }
    await fs.writeFile(f.serversFile, '{invalid secret text');
    await assert.rejects(loadRegistry({ serversFile: f.serversFile }), error => !error.message.includes('secret text'));
    await fs.writeFile(f.serversFile, JSON.stringify(f.config));
    await writeEnv(path.join(f.dir, 'beta.env'), { ...f.second.env, SSH_PORT: 'invalid' });
    await assert.rejects(loadRegistry({ serversFile: f.serversFile }), /Profile beta:/);
    assert.equal(f.first.attempts.length + f.second.attempts.length, 0);
  } finally { await f.close(); }
});

test('all tools require explicit targets; parallel commands, diagnostics and audits stay isolated', async () => {
  const f = await fixture(); let app;
  try {
    app = await f.open();
    const listing = await app.client.listTools(); assert.equal(listing.tools.length, 27);
    for (const tool of listing.tools.filter(tool => tool.name !== 'ssh_servers_list')) assert.ok(tool.inputSchema.required.includes('server_id'), tool.name);
    const servers = await app.value('ssh_servers_list'); assert.equal(servers.servers.length, 2);
    assert.equal(f.first.attempts.length + f.second.attempts.length, 0);
    assert.ok(servers.servers.every(profile => Object.keys(profile).every(key => ['server_id', 'name', 'host', 'port', 'username', 'auth_method'].includes(key))));
    const safeList = JSON.stringify(servers);
    for (const secret of [f.first.env.SSH_PASSWORD, f.second.env.SSH_PASSWORD, 'alpha.env', 'beta.env']) assert.ok(!safeList.includes(secret));
    assert.ok((await app.call('ssh_exec', { command: 'synthetic' })).isError);
    const rejected = await app.call('ssh_exec', { server_id: 'unknown', command: 'synthetic' }); assert.ok(rejected.isError);
    assert.equal(JSON.parse(rejected.content[0].text).server_id, 'unknown');
    assert.equal(f.first.attempts.length + f.second.attempts.length, 0);
    const results = await Promise.all(['alpha', 'beta', 'alpha', 'beta'].map(server_id => app.value('ssh_exec', { server_id, command: 'synthetic' })));
    for (const [index, value] of results.entries()) { assert.equal(value.server_id, index % 2 ? 'beta' : 'alpha'); assert.equal(value.stdout, value.server_id + '\n[REDACTED]\n'); }
    const probe = await app.value('ssh_network_probe', { server_id: 'beta', host: 'example.invalid', port: 443 }); assert.equal(probe.label, 'beta');
    if (publicCopy) assert.equal(f.second.actions.at(-1).diagnostic_user, 'diagnostics-beta');
    const registry = await loadRegistry({ serversFile: f.serversFile, env: f.env });
    for (const profile of registry.profiles.values()) {
      const audit = await fs.readFile(path.join(profile.stateDir, 'audit.jsonl'), 'utf8');
      const entries = audit.trim().split('\n').map(JSON.parse); assert.ok(entries.every(entry => entry.server_id === profile.id));
      assert.ok(!audit.includes(f.first.env.SSH_PASSWORD) && !audit.includes(f.second.env.SSH_PASSWORD));
    }
    await f.second.close(); f.second.close = async () => {};
    assert.ok((await app.call('ssh_exec', { server_id: 'beta', command: 'synthetic' })).isError);
    assert.equal((await app.value('ssh_exec', { server_id: 'alpha', command: 'synthetic' })).server_id, 'alpha');
    assert.ok(!app.errors().includes(f.first.env.SSH_PASSWORD));
  } finally { if (app) await app.close(); await f.close(); }
});

test('same request IDs, resource locks and file paths do not cross servers', async () => {
  const f = await fixture(); let app;
  try {
    app = await f.open();
    const spec = { request_id: 'same-request', command: 'synthetic-operation', resource: '/srv/app' };
    const a = await app.value('ssh_operation_start', { ...spec, server_id: 'alpha' });
    const b = await app.value('ssh_operation_start', { ...spec, server_id: 'beta' });
    assert.notEqual(a.operation_id, b.operation_id);
    assert.equal((await app.value('ssh_operation_start', { ...spec, server_id: 'alpha' })).operation_id, a.operation_id);
    assert.equal(f.first.operations.size, 1); assert.equal(f.second.operations.size, 1);
    const busy = await app.call('ssh_operation_start', { ...spec, request_id: 'different-request', server_id: 'alpha' });
    assert.ok(busy.isError); const error = JSON.parse(busy.content[0].text); assert.equal(error.code, 'resource_busy'); assert.equal(error.details.blocker.operation_id, a.operation_id);
    assert.equal((await app.value('ssh_deploy_lock_status', { server_id: 'beta', resource: '/srv/app' })).holder.operation_id, b.operation_id);
    assert.equal((await app.value('ssh_operation_list', { server_id: 'alpha' })).operations.length, 1);
    assert.equal((await app.value('ssh_operation_report', { server_id: 'beta', operation_id: b.operation_id })).label, 'beta');
    assert.ok((await app.call('ssh_operation_report', { server_id: 'beta', operation_id: a.operation_id })).isError);
    await app.value('ssh_operation_cancel', { server_id: 'alpha', operation_id: a.operation_id });
    assert.equal(f.second.operations.get(b.operation_id).state, 'running');
    await app.value('ssh_write_file', { server_id: 'alpha', path: '/same.txt', content: 'alpha-file', expected_sha256: null });
    await app.value('ssh_write_file', { server_id: 'beta', path: '/same.txt', content: 'beta-file', expected_sha256: null });
    assert.equal((await app.value('ssh_read_file', { server_id: 'alpha', path: '/same.txt' })).content, 'alpha-file');
    assert.equal((await app.value('ssh_read_file', { server_id: 'beta', path: '/same.txt' })).content, 'beta-file');
  } finally { if (app) await app.close(); await f.close(); }
});

test('downloads resume after MCP restart, retain snapshots and reject other-server transfers', { timeout: 60000 }, async () => {
  const f = await fixture(); let app;
  try {
    app = await f.open();
    // Changing credential files after startup must not switch a worker's connection.
    await writeEnv(path.join(f.dir, 'alpha.env'), f.second.env);
    f.first.holdAfterFirstBatch();
    const a = await app.value('ssh_download_file', { server_id: 'alpha', remote_path: '/dump.bin', local_path: 'transfers/same.bin', encrypt: true, wait_ms: 0 });
    await until(async () => { const status = await app.value('ssh_download_status', { server_id: 'alpha', transfer_id: a.transfer_id }); assert.notEqual(status.state, 'interrupted', 'Synthetic download must make progress: ' + JSON.stringify(status) + ', actions=' + f.first.actions.map(action => action.action).join(',')); return status.bytes_downloaded > 0; });
    await app.value('ssh_download_pause', { server_id: 'alpha', transfer_id: a.transfer_id });
    f.first.releaseReads();
    await until(async () => (await app.value('ssh_download_status', { server_id: 'alpha', transfer_id: a.transfer_id })).state === 'paused');
    assert.ok((await app.call('ssh_download_resume', { server_id: 'beta', transfer_id: a.transfer_id })).isError);
    assert.ok((await app.call('ssh_download_pause', { server_id: 'beta', transfer_id: a.transfer_id })).isError);
    assert.ok((await app.call('ssh_download_cleanup', { server_id: 'beta', transfer_id: a.transfer_id, expired_only: false })).isError);
    assert.equal((await app.value('ssh_download_list', { server_id: 'beta' })).transfers.length, 0);
    await writeEnv(path.join(f.dir, 'alpha.env'), f.first.env);
    const b = await app.value('ssh_download_file', { server_id: 'beta', remote_path: '/dump.bin', local_path: 'transfers/same.bin', wait_ms: 0 });
    const bDone = await until(async () => { const s = await app.value('ssh_download_status', { server_id: 'beta', transfer_id: b.transfer_id }); assert.notEqual(s.state, 'interrupted', JSON.stringify(s)); return s.state === 'completed' && s; });
    assert.equal(await fs.readFile(bDone.path, 'utf8'), 'beta-dump');
    await app.close(); app = await f.open();
    assert.equal((await app.value('ssh_download_list', { server_id: 'alpha' })).transfers[0].transfer_id, a.transfer_id);
    await app.value('ssh_download_resume', { server_id: 'alpha', transfer_id: a.transfer_id });
    const aDone = await until(async () => { const s = await app.value('ssh_download_status', { server_id: 'alpha', transfer_id: a.transfer_id }); return s.state === 'completed' && s; });
    assert.notEqual(aDone.path, bDone.path);
    const exported = await app.value('ssh_download_decrypt', { server_id: 'alpha', transfer_id: a.transfer_id, local_path: 'transfers/plain.bin' });
    const hash = crypto.createHash('sha256').update(await fs.readFile(exported.path)).digest('hex');
    assert.equal(hash, aDone.sha256); assert.equal(hash, crypto.createHash('sha256').update(f.first.files.get('/dump.bin')).digest('hex'));
    await app.value('ssh_download_cleanup', { server_id: 'alpha', transfer_id: a.transfer_id, expired_only: false });
    assert.equal(await fs.readFile(bDone.path, 'utf8'), 'beta-dump'); assert.ok(await fs.stat(exported.path));
  } finally { if (app) await app.close(); await f.close(); }
});

test('worker environment excludes credentials; snapshots mask all loaded secrets', async () => {
  const filtered = workerEnvironment({ Path: 'synthetic-path', SystemRoot: 'synthetic-windows', SSH_PASSWORD: 'beta-secret', SSH_AUTH_SOCK: 'other-agent', TOKEN: 'other-token', NODE_OPTIONS: 'unsafe' });
  assert.deepEqual(filtered, { Path: 'synthetic-path', SystemRoot: 'synthetic-windows' });
  const f = await fixture();
  try {
    await loadRegistry({ serversFile: f.serversFile, env: f.env });
    assert.equal(redact(f.first.env.SSH_PASSWORD + ' ' + f.second.env.SSH_PASSWORD), '[REDACTED] [REDACTED]');
    const credentialFile = path.join(f.dir, 'password.txt'); await fs.writeFile(credentialFile, 'synthetic-file-snapshot', { mode: 0o600 });
    const { SSH_PASSWORD, ...env } = f.first.env;
    const snapshot = await snapshotEnvironment({ ...env, SSH_PASSWORD_FILE: credentialFile });
    await fs.writeFile(credentialFile, 'changed-file-secret');
    assert.equal(snapshot.SSH_PASSWORD, 'synthetic-file-snapshot'); assert.equal(snapshot.SSH_PASSWORD_FILE, undefined);
    const normalized = await snapshotEnvironment({ ...f.first.env, SSH_HOST: 'LOCALHOST', SSH_PORT: '022' });
    assert.equal(normalized.SSH_HOST, 'localhost'); assert.equal(normalized.SSH_PORT, '22');
  } finally { await f.close(); }
});

test('private-key snapshots survive edited key files and empty passphrase-file changes', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-key-snapshot-'));
  try {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const file = path.join(dir, 'id_key'), phrase = path.join(dir, 'passphrase.txt');
    await fs.writeFile(file, privateKey.export({ type: 'pkcs1', format: 'pem' }), { mode: 0o600 });
    await fs.writeFile(phrase, '', { mode: 0o600 });
    const env = { SSH_HOST: 'example.invalid', SSH_USERNAME: 'test-user', SSH_AUTH_METHOD: 'private_key', SSH_PRIVATE_KEY_PATH: file, SSH_KEY_PASSPHRASE_FILE: phrase,
      SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '') };
    const snapshot = await snapshotEnvironment(env);
    await fs.writeFile(file, 'changed key file'); await fs.writeFile(phrase, 'changed-passphrase');
    assert.equal(snapshot.SSH_KEY_PASSPHRASE_FILE, undefined);
    const options = await buildConnectOptions(snapshot); assert.ok(options.privateKey.includes(Buffer.from('PRIVATE KEY')));
    assert.equal(redact(snapshot.__privateKey), '[REDACTED]');
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('Windows DPAPI works in the filtered worker environment', { skip: process.platform !== 'win32' }, () => {
  const module = new URL('../src/local-state.js', import.meta.url).href;
  const script = `import { sealKey, openKey } from ${JSON.stringify(module)}; const key = Buffer.alloc(32, 7); const sealed = await sealKey(key); if (!(await openKey(sealed)).equals(key)) throw new Error('DPAPI mismatch'); console.log('verified');`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { env: workerEnvironment(), encoding: 'utf8', timeout: 35000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr || result.error?.message); assert.equal(result.stdout.trim(), 'verified');
});

test('single-profile multi mode still requires server_id; public CLI checks never connect', async () => {
  const f = await fixture(); let app;
  try {
    await fs.writeFile(f.serversFile, JSON.stringify({ version: 1, servers: [f.config.servers[0]] }));
    if (publicCopy) {
      const run = args => spawnSync(process.execPath, [entry, ...args], { env: f.env, encoding: 'utf8', cwd: os.tmpdir() });
      const checked = run(['--servers-file', f.serversFile, '--check-config']); assert.equal(checked.status, 0, checked.stderr);
      assert.equal(JSON.parse(checked.stdout).servers[0].server_id, 'alpha');
      assert.ok(!checked.stdout.includes(f.first.env.SSH_PASSWORD)); assert.equal(f.first.attempts.length, 0);
      assert.notEqual(run(['--servers-file']).status, 0);
      assert.notEqual(run(['--servers-file', f.serversFile, '--env-file', 'ignored.env']).status, 0);
      assert.notEqual(run(['--servers-file', f.serversFile, '--servers-file', f.serversFile]).status, 0);
    }
    app = await f.open(); assert.ok((await app.call('ssh_exec', { command: 'synthetic' })).isError);
    assert.equal((await app.value('ssh_exec', { server_id: 'alpha', command: 'synthetic' })).server_id, 'alpha');
  } finally { if (app) await app.close(); await f.close(); }
});

test('legacy registry keeps state and operation IDs without normalizing existing inputs', async () => {
  const env = { SSH_HOST: 'EXAMPLE.INVALID', SSH_PORT: '022', SSH_USERNAME: 'test-user', SSH_MCP_STATE_DIR: path.join(os.tmpdir(), 'legacy-state') };
  const registry = await loadRegistry({ env }); assert.equal(registry.multi, false);
  const profile = registry.profiles.get('default'); assert.equal(profile.env.SSH_HOST, env.SSH_HOST); assert.equal(profile.env.SSH_PORT, '022');
  assert.equal(operationId('old-request', profile.env), operationId('old-request', env));
  const identity = publicCopy ? [env.SSH_HOST.trim().toLowerCase(), String(Number(env.SSH_PORT)), env.SSH_USERNAME] : [env.SSH_HOST, env.SSH_PORT, env.SSH_USERNAME];
  assert.equal(operationId('old-request', profile.env), crypto.createHash('sha256').update([...identity, 'old-request'].join('\0')).digest('hex').slice(0, 32));
  if (!publicCopy) assert.equal(profile.stateDir, env.SSH_MCP_STATE_DIR);
  else assert.equal(profile.stateDir, path.join(env.SSH_MCP_STATE_DIR, crypto.createHash('sha256').update(identity.join('\0')).digest('hex').slice(0, 24)));
  if (!publicCopy) {
    const options = await buildConnectOptions({ SSH_HOST: 'example.invalid', SSH_PASSWORD: 'synthetic-legacy-password' });
    assert.equal(options.username, 'root'); assert.deepEqual(options.authHandler, ['password']);
  }
});
