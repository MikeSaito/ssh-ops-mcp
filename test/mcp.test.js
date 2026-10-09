import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { testServer } from './helpers.js';
const root = path.resolve(import.meta.dirname, '..');
const bin = path.join(root, 'bin/ssh-ops-mcp.js');

test('public entrypoint initializes MCP and executes over the test SSH server', async () => {
  const server = await testServer(), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-mcp-'));
  const client = new Client({ name: 'public-test', version: '1.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [bin], cwd: dir, env: { ...server.env, SSH_MCP_STATE_DIR: dir }, stderr: 'pipe' });
  let errors = ''; transport.stderr?.on('data', data => { errors += data.toString(); });
  try {
    await client.connect(transport);
    const listed = await client.listTools(); assert.equal(listed.tools.length, 26);
    assert.ok(listed.tools.some(tool => tool.name === 'ssh_operation_report'));
    assert.ok(listed.tools.find(tool => tool.name === 'ssh_operation_start').inputSchema.properties.steps);
    assert.ok(listed.tools.find(tool => tool.name === 'ssh_operation_list').inputSchema.properties.cursor);
    const rejected = await client.callTool({ name: 'ssh_operation_start', arguments: { request_id: 'invalid', command: 'true', steps: [{ name: 'Invalid', command: 'true' }] } });
    assert.ok(rejected.isError); assert.ok(rejected.content[0].text.includes('exactly one'));
    const result = await client.callTool({ name: 'ssh_exec', arguments: { command: 'synthetic-test-command' } });
    assert.ok(!result.isError, JSON.stringify(result));
    const value = JSON.parse(result.content[0].text);
    assert.equal(value.stdout, 'synthetic-output\n'); assert.equal(value.exitCode, 0);
    assert.ok(!errors.includes('synthetic-password'));
  } finally { await client.close(); await transport.close(); await server.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
test('env-file works from a different cwd, CLI is secret-safe and rejects invalid config', async () => {
  const server = await testServer(), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-cli-'));
  // Explicit test environment: never inherit a developer SSH password/profile.
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('SSH_')));
  try {
    const file = path.join(dir, 'server.env');
    await fs.writeFile(file, Object.entries(server.env).map(([key, value]) => key + '=' + value).join('\n'), { mode: 0o600 });
    const run = args => spawnSync(process.execPath, [bin, ...args], { cwd: os.tmpdir(), env: cleanEnv, encoding: 'utf8' });
    const valid = run(['--env-file', file, '--check-config']);
    assert.equal(valid.status, 0, valid.stderr); assert.equal(JSON.parse(valid.stdout).valid, true);
    assert.ok(!valid.stdout.includes('synthetic-password')); assert.equal(server.attempts.length, 0);
    assert.notEqual(run(['--env-file']).status, 0); assert.notEqual(run(['--env-file', path.join(dir, 'missing')]).status, 0);
    assert.equal(run(['--help']).status, 0); assert.equal(run(['--version']).stdout.trim(), '1.1.0');
  } finally { await server.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
