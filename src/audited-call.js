// Audit failure must never disguise an already executed action as a failed launch.
export async function auditedCall(record, entry, action) {
  try { await record({ ...entry, outcome: 'requested' }); }
  catch { return { error: Object.assign(new Error('Audit unavailable; this call was not executed.'), { code: 'audit_unavailable', transport: { phase: 'audit', dispatch_state: 'not_sent' } }), warnings: [] }; }
  let value, error;
  try { value = await action(); } catch (caught) { error = caught; }
  const operation_id = value?.operation_id || error?.operation_id || entry.operation_id;
  const warnings = [];
  try { await record({ ...entry, operation_id, outcome: error ? 'error_or_unknown' : 'returned' }); }
  catch { warnings.push({ code: 'audit_write_failed', ...(operation_id ? { operation_id } : {}), message: 'The action result is preserved, but its final audit entry could not be saved. Do not replay the action.' }); }
  return { value, error, warnings };
}
