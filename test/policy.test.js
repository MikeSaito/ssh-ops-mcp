import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { parsePolicy, permits, loadPolicy } from '../src/policy.js';
import { loadRegistry, snapshotEnvironment, workerEnvironment, connectionIdentity } from '../src/config.js';
import { toolNames } from '../src/policy.js';
import { createTools } from '../src/tools.js';
import { testServer } from './helpers.js';

test('access policy is explicit, deny-by-default and validates tool names', () => {
  assert.deepEqual([...toolNames].sort(), createTools({ env: {}, stateDir: '/unused' }).map(tool => tool.name).sort());
  const p = parsePolicy({ version: 1, servers: { alpha: { tools: ['ssh_server_info'] } } });
  assert.equal(permits(p, 'alpha', 'ssh_server_info'), true);
  assert.equal(permits(p, 'alpha', 'ssh_exec'), false);
  assert.equal(permits(p, 'beta', 'ssh_server_info'), false);
  for (const value of [{}, { version: 1, servers: {} }, { version: 1, servers: { alpha: { tools: ['*'] } } }, { version: 1, servers: { alpha: { tools: [] } } }])
    assert.throws(() => parsePolicy(value));
});

test('transit needs explicit authorization and snapshots retain only the selected route', async () => {
  const first = await testServer(), second = await testServer();
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-route-policy-'));
  try {
    const manifest = path.join(dir, 'servers.json'), policyFile = path.join(dir, 'policy.json');
    await fs.writeFile(path.join(dir, 'target.env'), Object.entries(first.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'jump.env'), Object.entries(second.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    await fs.writeFile(manifest, JSON.stringify({ version: 1, servers: [
      { id: 'target', env_file: 'target.env', via: 'jump' }, { id: 'jump', env_file: 'jump.env' },
      { id: 'excluded', env_file: 'unread.env' },
    ] }), { mode: 0o600 });
    const policy = { version: 1, servers: { target: { tools: ['ssh_read_file'] } } };
    await fs.writeFile(policyFile, JSON.stringify(policy), { mode: 0o600 });
    await assert.rejects(loadRegistry({ serversFile: manifest, policyFile }), /authorize the transit/);
    await fs.writeFile(policyFile, JSON.stringify({ ...policy, transit_servers: ['jump'] }), { mode: 0o600 });
    const registry = await loadRegistry({ serversFile: manifest, policyFile });
    assert.deepEqual([...registry.profiles.keys()], ['target']);
    const selected = registry.profiles.get('target').env, snapshot = await snapshotEnvironment(selected);
    assert.equal(snapshot.__jump.SSH_PORT, second.env.SSH_PORT);
    assert.equal(snapshot.SSH_PORT, first.env.SSH_PORT);
    assert.equal(connectionIdentity(snapshot), connectionIdentity(selected));
    assert.deepEqual(workerEnvironment({ PATH: 'synthetic', SSH_PASSWORD: 'excluded', OTHER_TOKEN: 'excluded' }), { PATH: 'synthetic' });
    assert.equal(first.attempts.length + second.attempts.length, 0);
    for (const via of ['target', 'missing']) {
      await fs.writeFile(manifest, JSON.stringify({ version: 1, servers: [{ id: 'target', env_file: 'target.env', via }, { id: 'jump', env_file: 'jump.env' }] }));
      await assert.rejects(loadRegistry({ serversFile: manifest, policyFile }), /via must reference/);
    }
  } finally { await first.close(); await second.close(); await fs.rm(dir, { recursive: true, force: true }); }
});

test('excluded profiles are not read and direct calls enforce per-server policy', async () => {
  const fixture = await testServer(), other = await testServer(), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-policy-'));
  let client, transport;
  try {
    const servers = path.join(dir, 'servers.json'), policy = path.join(dir, 'policy.json');
    await fs.writeFile(path.join(dir, 'alpha.env'), Object.entries(fixture.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'beta.env'), Object.entries(other.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    await fs.writeFile(servers, JSON.stringify({ version: 1, servers: [
      { id: 'alpha', env_file: 'alpha.env' }, { id: 'beta', env_file: 'beta.env' }, { id: 'excluded', env_file: 'missing-private.env' },
    ] }), { mode: 0o600 });
    await fs.writeFile(policy, JSON.stringify({ version: 1, servers: { alpha: { tools: ['ssh_server_info', 'ssh_exec'] }, beta: { tools: ['ssh_server_info'] } } }), { mode: 0o600 });
    const registry = await loadRegistry({ serversFile: servers, policyFile: policy });
    assert.deepEqual([...registry.profiles.keys()], ['alpha', 'beta']);
    assert.equal(fixture.attempts.length, 0);
    const root = path.resolve(import.meta.dirname, '..');
    const publicCopy = await fs.access(path.join(root, 'bin/ssh-ops-mcp.js')).then(() => true, () => false);
    client = new Client({ name: 'policy-test', version: '1' });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SSH_')));
    transport = new StdioClientTransport({ command: process.execPath,
      args: [path.join(root, publicCopy ? 'bin/ssh-ops-mcp.js' : 'src/index.js'), '--servers-file', servers, '--policy-file', policy],
      env: { ...env, SSH_MCP_STATE_DIR: path.join(dir, 'state') }, stderr: 'pipe' });
    await client.connect(transport);
    assert.deepEqual((await client.listTools()).tools.map(tool => tool.name).sort(), ['ssh_exec', 'ssh_server_info', 'ssh_servers_list']);
    const list = await client.callTool({ name: 'ssh_servers_list', arguments: {} });
    assert.deepEqual(JSON.parse(list.content[0].text).servers.map(server => server.server_id), ['alpha', 'beta']);
    const denied = await client.callTool({ name: 'ssh_exec', arguments: { server_id: 'beta', command: 'do-not-run' } });
    assert.equal(denied.isError, true); assert.equal(fixture.attempts.length, 0);
    assert.equal(other.attempts.length, 0);
    assert.equal((await client.callTool({ name: 'ssh_server_info', arguments: { server_id: 'excluded' } })).isError, true);
    const hidden = await client.callTool({ name: 'ssh_write_file', arguments: { server_id: 'alpha' } }).catch(error => ({ isError: true }));
    assert.equal(hidden.isError, true); assert.equal(fixture.attempts.length, 0);
    assert.equal((await client.callTool({ name: 'ssh_server_info', arguments: { server_id: 'alpha' } })).isError, undefined);
    assert.equal(await fs.access(path.join(dir, 'state')).then(() => true, () => false), true);
    await fs.writeFile(policy, '{private secret broken JSON');
    await assert.rejects(loadPolicy(policy), error => !error.message.includes('private secret'));
  } finally { await client?.close(); await transport?.close(); await fixture.close(); await other.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
