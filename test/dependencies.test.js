import test from 'node:test';
import assert from 'node:assert/strict';
import dotenv from 'dotenv';
import { z } from 'zod';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createTools } from '../src/tools.js';
import { serverIdPattern } from '../src/config.js';

test('dotenv parses quoted profile values without changing the process environment', () => {
  const before = { ...process.env };
  const parsed = dotenv.parse(Buffer.from([
    '# synthetic profile',
    'SSH_HOST=example.invalid',
    'SSH_PASSWORD="synthetic # password = with spaces"',
    "SSH_KEY_PASSPHRASE='  synthetic passphrase  '",
    'SSH_PORT=22 # comment',
    'EMPTY=',
    '',
  ].join('\r\n')));
  assert.deepEqual(parsed, {
    SSH_HOST: 'example.invalid',
    SSH_PASSWORD: 'synthetic # password = with spaces',
    SSH_KEY_PASSPHRASE: '  synthetic passphrase  ',
    SSH_PORT: '22',
    EMPTY: '',
  });
  assert.deepEqual({ ...process.env }, before);
});

test('SDK lists every tool schema and validates defaults before invoking handlers', async () => {
  // Replace all handlers: this test must never run SSH, write files or start workers.
  const definitions = createTools({ env: { SSH_HOST: 'example.invalid' }, stateDir: '/synthetic-state', downloads: {} });
  const server = new McpServer({ name: 'dependency-test', version: '1' });
  const client = new Client({ name: 'dependency-test-client', version: '1' });
  const calls = [];
  for (const definition of definitions) {
    server.registerTool(definition.name, {
      description: definition.description,
      inputSchema: {
        ...definition.inputSchema,
        server_id: z.string().regex(serverIdPattern).describe('Explicit synthetic server ID.'),
      },
    }, async args => {
      calls.push({ name: definition.name, args });
      return { content: [{ type: 'text', text: JSON.stringify(args) }] };
    });
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const listed = await client.listTools();
    assert.equal(listed.tools.length, 26);
    for (const tool of listed.tools) {
      assert.equal(tool.inputSchema.type, 'object', tool.name);
      assert.ok(tool.inputSchema.required.includes('server_id'), tool.name);
      assert.equal(tool.inputSchema.properties.server_id.description, 'Explicit synthetic server ID.');
    }
    const schema = name => listed.tools.find(tool => tool.name === name).inputSchema;
    assert.equal(schema('ssh_operation_start').properties.timeout_seconds.default, 3600);
    assert.equal(schema('ssh_operation_start').properties.steps.type, 'array');
    assert.equal(schema('ssh_operation_logs').properties.limit_bytes.default, 16384);
    assert.ok(schema('ssh_write_file').required.includes('expected_sha256'));
    const call = async (name, args) => {
      const result = await client.callTool({ name, arguments: { server_id: 'alpha', ...args } });
      assert.ok(!result.isError, JSON.stringify(result));
      assert.equal(result.structuredContent, undefined);
      return JSON.parse(result.content[0].text);
    };
    const operation = await call('ssh_operation_start', { request_id: 'synthetic', command: 'true' });
    assert.equal(operation.timeout_seconds, 3600);
    assert.equal(Object.hasOwn(operation, 'steps'), false);
    const logs = await call('ssh_operation_logs', { operation_id: 'a'.repeat(32) });
    assert.deepEqual(logs, { server_id: 'alpha', operation_id: 'a'.repeat(32), stream: 'stdout', offset: 0, limit_bytes: 16384 });
    const write = await call('ssh_write_file', { path: '/synthetic.conf', content: '', expected_sha256: null });
    assert.equal(write.expected_sha256, null);
    assert.equal(write.backup, true);
    const download = await call('ssh_download_file', { remote_path: '/synthetic.bin', local_path: 'synthetic.bin' });
    assert.equal(download.encrypt, false);
    assert.equal(download.overwrite, false);
    assert.equal(download.retention_days, 7);
    assert.equal(download.wait_ms, 1000);
    const accepted = calls.length;
    for (const [name, args] of [
      ['ssh_exec', { command: 'true' }],
      ['ssh_exec', { server_id: '../invalid', command: 'true' }],
      ['ssh_exec', { server_id: 'alpha', command: '' }],
      ['ssh_exec', { server_id: 'alpha', command: 'true', timeout_ms: '1000' }],
      ['ssh_operation_start', { server_id: 'alpha', request_id: 'synthetic', command: 'true', timeout_seconds: 0 }],
      ['ssh_write_file', { server_id: 'alpha', path: '/synthetic.conf', content: '' }],
      ['ssh_write_file', { server_id: 'alpha', path: '/synthetic.conf', content: '', expected_sha256: 'invalid' }],
    ]) {
      const result = await client.callTool({ name, arguments: args });
      assert.ok(result.isError, name + ': ' + JSON.stringify(args));
    }
    assert.equal(calls.length, accepted, 'Invalid input must not reach a handler');
  } finally {
    await client.close();
    await server.close();
  }
});
