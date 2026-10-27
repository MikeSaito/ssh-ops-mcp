import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { workerEnvironment } from '../src/config.js';

test('default package .env selects a private manifest and policy before registry loading', async () => {
  const root = path.resolve(import.meta.dirname, '..'), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-env-pointer-'));
  try {
    await fs.cp(path.join(root, 'src'), path.join(dir, 'src'), { recursive: true });
    await fs.copyFile(path.join(root, 'package.json'), path.join(dir, 'package.json'));
    await fs.symlink(path.join(root, 'node_modules'), path.join(dir, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
    await fs.writeFile(path.join(dir, 'profile.env'), 'SSH_HOST=example.invalid\nSSH_USERNAME=synthetic\nSSH_AUTH_METHOD=password\nSSH_PASSWORD=synthetic-env-pointer\nSSH_HOST_FINGERPRINT_SHA256=SHA256:' + 'A'.repeat(43) + '\n', { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'servers.json'), JSON.stringify({ version: 1, servers: [{ id: 'alpha', env_file: 'profile.env' }] }), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'policy.json'), JSON.stringify({ version: 1, servers: { alpha: { tools: ['ssh_server_info'] } } }), { mode: 0o600 });
    const manifest = path.join(dir, 'servers.json').replaceAll('\\', '/'), policy = path.join(dir, 'policy.json').replaceAll('\\', '/');
    await fs.writeFile(path.join(dir, '.env'), 'SSH_MCP_SERVERS_FILE=' + manifest + '\nSSH_MCP_POLICY_FILE=' + policy + '\n', { mode: 0o600 });
    const result = spawnSync(process.execPath, ['--', path.join(dir, 'src/index.js'), '--check-config'], { cwd: os.tmpdir(), env: workerEnvironment(), encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, result.stderr);
    const data = JSON.parse(result.stdout);
    assert.equal(data.multi_server, true); assert.equal(data.policy_applied, true);
    assert.deepEqual(data.servers.map(item => item.server_id), ['alpha']);
    assert.ok(!result.stdout.includes('synthetic-env-pointer'));
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
