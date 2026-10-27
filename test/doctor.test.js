import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { doctor } from '../src/doctor.js';
import { testServer } from './helpers.js';

test('doctor defaults to local checks and never connects or prints credentials', async () => {
  const server = await testServer(), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-doctor-'));
  try {
    const profile = { id: 'alpha', env: server.env, stateDir: path.join(dir, 'not-created') };
    const report = await doctor({ multi: true, profiles: new Map([['alpha', profile]]) });
    assert.equal(report.ready, true); assert.equal(report.network_requested, false); assert.equal(server.attempts.length, 0);
    assert.equal(await fs.access(profile.stateDir).then(() => true, () => false), false);
    assert.ok(!JSON.stringify(report).includes(server.env.SSH_PASSWORD));
    const root = path.resolve(import.meta.dirname, '..'), publicCopy = await fs.access(path.join(root, 'bin/ssh-ops-mcp.js')).then(() => true, () => false);
    const entry = path.join(root, publicCopy ? 'bin/ssh-ops-mcp.js' : 'src/index.js');
    const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SSH_')));
    const file = path.join(dir, 'profile.env'); await fs.writeFile(file, Object.entries(server.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    const run = args => spawnSync(process.execPath, ['--', entry, ...args], { encoding: 'utf8', env: { ...clean, SSH_MCP_STATE_DIR: path.join(dir, 'cli-state') }, windowsHide: true });
    const good = run(['--env-file', file, '--doctor']); assert.equal(good.status, 0, good.stderr); assert.equal(JSON.parse(good.stdout).ready, true);
    assert.equal(server.attempts.length, 0);
    const client = run(['--env-file', file, '--print-client-config']); assert.equal(client.status, 0);
    assert.ok(!client.stdout.includes(server.env.SSH_PASSWORD)); assert.ok(JSON.parse(client.stdout).mcpServers.ssh_ops.args.includes('--connection-file'));
    const bad = run(['--env-file', path.join(dir, 'missing'), '--doctor']); assert.notEqual(bad.status, 0); assert.equal(JSON.parse(bad.stdout).ready, false);
    await assert.rejects(doctor({ multi: true, profiles: new Map([['alpha', profile]]) }, { connect: true }), /Select an allowed server/);
  } finally { await server.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
