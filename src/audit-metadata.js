const errorCodes = new Set([
  'ssh_connection_failed', 'ssh_authentication_failed', 'ssh_host_key_rejected',
  'ssh_connect_timeout', 'ssh_connection_refused', 'ssh_dns_failed', 'ssh_connection_closed',
  'ssh_transit_lost', 'ssh_transit_timeout', 'ssh_transit_refused',
  'ssh_command_timeout', 'ssh_exec_failed', 'ssh_connection_lost', 'ssh_exit_status_missing',
  'ssh_sftp_connection_lost', 'ssh_sftp_failed', 'ssh_sftp_open_failed', 'ssh_sftp_timeout',
  'ssh_helper_failed', 'ssh_helper_invalid_response', 'resource_busy',
  'filesystem_no_space', 'filesystem_permission_denied', 'filesystem_not_found',
  'filesystem_busy', 'filesystem_exists', 'operation_unavailable', 'remote_exit_nonzero',
  'remote_signal', 'unclassified_error',
]);
const filesystemCodes = new Map([
  ['ENOSPC', 'filesystem_no_space'], ['EACCES', 'filesystem_permission_denied'],
  ['EPERM', 'filesystem_permission_denied'], ['ENOENT', 'filesystem_not_found'],
  ['EBUSY', 'filesystem_busy'], ['EEXIST', 'filesystem_exists'],
]);
const phases = new Set(['connect', 'authentication', 'host_verification', 'transit', 'exec', 'sftp', 'response']);
const dispatchStates = new Set(['not_sent', 'unknown']);
const operationStates = new Set(['starting', 'running', 'completed', 'failed', 'timed_out', 'cancelled', 'process_lost', 'connection_lost_or_unavailable']);

// Unknown codes can contain secrets; never serialize them or infer from error text.
export function auditErrorMetadata(error) {
  const code = filesystemCodes.get(error?.code) || (errorCodes.has(error?.code) ? error.code : 'unclassified_error');
  const connection = error?.transport || error?.connection;
  return { error_code: code,
    ...(phases.has(connection?.phase) ? { phase: connection.phase } : {}),
    ...(dispatchStates.has(connection?.dispatch_state) ? { dispatch_state: connection.dispatch_state } : {}) };
}

export function auditResultMetadata(tool, value) {
  if (!value || typeof value !== 'object') return {};
  if (tool === 'ssh_exec' || tool === 'ssh_server_info') {
    const exit = value.exitCode;
    return {
      ...(Number.isInteger(exit) && exit >= -2147483648 && exit <= 2147483647 ? { exit_code: exit } : {}),
      ...(value.signal ? { error_code: 'remote_signal' } : Number.isInteger(exit) && exit !== 0 ? { error_code: 'remote_exit_nonzero' } : {}),
    };
  }
  if (!tool?.startsWith('ssh_operation_')) return {};
  return {
    ...(operationStates.has(value.state) ? { operation_state: value.state } : {}),
    ...(value.state === 'connection_lost_or_unavailable'
      ? auditErrorMetadata({ code: value.code || 'operation_unavailable', connection: value.connection }) : {}),
  };
}

// Apply the same allow-list at the file writer, independently of its caller.
export function safeAuditMetadata(entry) {
  return {
    ...(typeof entry.call_id === 'string' && /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(entry.call_id) ? { call_id: entry.call_id } : {}),
    ...(Number.isSafeInteger(entry.duration_ms) && entry.duration_ms >= 0 ? { duration_ms: entry.duration_ms } : {}),
    ...(errorCodes.has(entry.error_code) ? { error_code: entry.error_code } : {}),
    ...(phases.has(entry.phase) ? { phase: entry.phase } : {}),
    ...(dispatchStates.has(entry.dispatch_state) ? { dispatch_state: entry.dispatch_state } : {}),
    ...(Number.isInteger(entry.exit_code) && entry.exit_code >= -2147483648 && entry.exit_code <= 2147483647 ? { exit_code: entry.exit_code } : {}),
    ...(operationStates.has(entry.operation_state) ? { operation_state: entry.operation_state } : {}),
  };
}
