export function sshError(code, phase, dispatchState, message) {
  const error = new Error(message);
  error.code = code;
  error.transport = Object.freeze({ phase, dispatch_state: dispatchState });
  return error;
}

export function connectionError(error) {
  let code = 'ssh_connection_failed', phase = 'connect';
  let message = 'SSH connection failed before command dispatch. Check server reachability and the selected profile.';
  if (error?.level === 'client-authentication') {
    code = 'ssh_authentication_failed'; phase = 'authentication';
    message = 'SSH authentication failed. Check the selected profile credentials; no fallback was attempted.';
  } else if (/verification failed|host denied/i.test(error?.message || '')) {
    code = 'ssh_host_key_rejected'; phase = 'host_verification';
    message = 'SSH host-key verification failed. Verify the key through a trusted channel; do not disable verification to retry.';
  } else if (error?.level === 'client-timeout' || error?.code === 'ETIMEDOUT') {
    code = 'ssh_connect_timeout';
    message = 'SSH connection or handshake timed out. Check reachability and SSH availability before retrying deliberately.';
  } else if (error?.code === 'ECONNREFUSED') {
    code = 'ssh_connection_refused';
    message = 'SSH connection refused. Check the SSH port, service and firewall.';
  } else if (['ENOTFOUND', 'EAI_AGAIN'].includes(error?.code)) {
    code = 'ssh_dns_failed';
    message = 'SSH hostname resolution failed. Check DNS and the selected profile host.';
  } else if (error?.code === 'SSH_CLOSED_BEFORE_READY') {
    code = 'ssh_connection_closed';
    message = 'SSH closed before authentication completed. Check SSH availability and server-side access limits.';
  }
  return sshError(code, phase, 'not_sent', message + ' No command was sent by this attempt. Earlier operations may still be running.');
}
