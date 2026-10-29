import test from 'node:test';
import assert from 'node:assert/strict';
import { auditedCall } from '../src/audited-call.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { audit } from '../src/security.js';

test('unavailable initial audit never dispatches the action', async () => {
  let called = 0;
  const result = await auditedCall(async () => { throw new Error('private error'); }, {}, async () => { called++; });
  assert.equal(called, 0); assert.equal(result.error.code, 'audit_unavailable');
  assert.equal(result.error.transport.dispatch_state, 'not_sent');
  assert.ok(!result.error.message.includes('private error'));
});
test('final audit failure preserves success and operation identity without retry', async () => {
  let calls = 0, records = 0;
  const value = { operation_id: 'a'.repeat(32), state: 'running' };
  const result = await auditedCall(async () => { if (++records === 2) throw new Error('private error'); }, {}, async () => { calls++; return value; });
  assert.equal(calls, 1); assert.equal(result.value, value); assert.equal(result.error, undefined);
  assert.equal(result.warnings[0].operation_id, value.operation_id); assert.equal(result.warnings[0].code, 'audit_write_failed');
  assert.ok(!JSON.stringify(result.warnings).includes('private error'));
});
test('failed final audit never masks original action error', async () => {
  let records = 0;
  const error = Object.assign(new Error('original'), { operation_id: 'b'.repeat(32) });
  const result = await auditedCall(async () => { if (++records === 2) throw new Error('audit'); }, {}, async () => { throw error; });
  assert.equal(result.error, error); assert.equal(result.warnings[0].operation_id, error.operation_id);
});

test('each concurrent call has its own correlated records and monotonic handler duration', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-audit-timing-'));
  try {
    const value = { stdout: 'private-output', exitCode: 0 };
    const values = await Promise.all(Array.from({ length: 5 }, () => auditedCall(
      entry => audit(root, entry), { tool: 'ssh_exec', operation_id: 'a'.repeat(32) },
      async () => { await new Promise(resolve => setTimeout(resolve, 20)); return value; })));
    assert.ok(values.every(result => result.value === value && !result.error));
    const text = await fs.readFile(path.join(root, 'audit.jsonl'), 'utf8');
    assert.ok(!text.includes('private-output'));
    const records = text.trim().split('\n').map(line => JSON.parse(line));
    const groups = Map.groupBy(records, entry => entry.call_id);
    assert.equal(groups.size, 5);
    for (const [id, pair] of groups) {
      assert.match(id, /^[a-f0-9-]{36}$/);
      assert.equal(pair.length, 2);
      assert.equal(pair[0].outcome, 'requested'); assert.equal(pair[0].duration_ms, undefined);
      assert.equal(pair[1].outcome, 'returned'); assert.equal(pair[1].exit_code, 0);
      assert.ok(Number.isSafeInteger(pair[1].duration_ms) && pair[1].duration_ms >= 15);
    }
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('only catalogued error metadata is logged and original errors are preserved', async () => {
  for (const [code, expected] of [['ssh_command_timeout', 'ssh_command_timeout'], ['ENOSPC', 'filesystem_no_space'], ['private-secret-code', 'unclassified_error'], [undefined, 'unclassified_error']]) {
    const records = [];
    const error = Object.assign(new Error('private-secret-message'), { code, transport: { phase: 'exec', dispatch_state: 'unknown', detail: 'private-secret-detail' } });
    const result = await auditedCall(async entry => records.push(entry), { tool: 'ssh_exec' }, async () => { throw error; });
    assert.equal(result.error, error);
    assert.equal(records[1].error_code, expected);
    assert.equal(records[1].phase, 'exec'); assert.equal(records[1].dispatch_state, 'unknown');
    assert.ok(!JSON.stringify(records).includes('private-secret'));
  }
});

test('returned remote failures stay returned while carrying safe diagnostics', async () => {
  for (const [tool, value, expected] of [
    ['ssh_exec', { exitCode: 7, stderr: 'private-error' }, { error_code: 'remote_exit_nonzero', exit_code: 7 }],
    ['ssh_operation_status', { state: 'connection_lost_or_unavailable', code: 'ssh_connection_lost', detail: 'private-error', connection: { phase: 'exec', dispatch_state: 'unknown' } }, { error_code: 'ssh_connection_lost', operation_state: 'connection_lost_or_unavailable' }],
    ['ssh_operation_status', { state: 'failed' }, { operation_state: 'failed' }],
  ]) {
    const records = [];
    const result = await auditedCall(async entry => records.push(entry), { tool }, async () => value);
    assert.equal(result.value, value); assert.equal(result.error, undefined);
    assert.equal(records[1].outcome, 'returned');
    for (const [key, item] of Object.entries(expected)) assert.equal(records[1][key], item);
    assert.ok(!JSON.stringify(records).includes('private-error'));
  }
});
