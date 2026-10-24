import test from 'node:test';
import assert from 'node:assert/strict';
import { auditedCall } from '../src/audited-call.js';

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
