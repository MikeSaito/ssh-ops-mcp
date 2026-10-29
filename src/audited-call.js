import { randomUUID } from 'node:crypto';
import { auditErrorMetadata, auditResultMetadata } from './audit-metadata.js';

// Audit failure must never disguise an already executed action as a failed launch.
export async function auditedCall(record, entry, action) {
  const call_id = randomUUID();
  try { await record({ ...entry, call_id, outcome: 'requested' }); }
  catch { return { error: Object.assign(new Error('Audit unavailable; this call was not executed.'), { code: 'audit_unavailable', transport: { phase: 'audit', dispatch_state: 'not_sent' } }), warnings: [] }; }
  const started = process.hrtime.bigint();
  let value, error;
  try { value = await action(); } catch (caught) { error = caught; }
  const duration_ms = Number((process.hrtime.bigint() - started) / 1000000n);
  const operation_id = value?.operation_id || error?.operation_id || entry.operation_id;
  const warnings = [];
  const diagnostics = error ? auditErrorMetadata(error) : auditResultMetadata(entry.tool, value);
  try { await record({ ...entry, call_id, operation_id, duration_ms, ...diagnostics, outcome: error ? 'error_or_unknown' : 'returned' }); }
  catch { warnings.push({ code: 'audit_write_failed', ...(operation_id ? { operation_id } : {}), message: 'The action result is preserved, but its final audit entry could not be saved. Do not replay the action.' }); }
  return { value, error, warnings };
}
