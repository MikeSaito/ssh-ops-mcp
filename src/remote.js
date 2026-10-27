import crypto from 'node:crypto';
import { exec, quote } from './ssh.js';
import { sshError } from './ssh-errors.js';
import { loadRemoteSource } from './helper-source.js';

const source = await loadRemoteSource();

export async function rpc(action, args = {}, timeoutMs = 30_000, env = process.env) {
  const bootstrap = 'import json,sys; p=json.loads(sys.stdin.read()); exec(compile(p["source"],"mcp-helper","exec"))';
  // Source and payload use stdin; command content is never argv or an action log.
  const response = await exec('python3 -c ' + quote(bootstrap), timeoutMs, JSON.stringify({ source, action, args, diagnostic_user: env.SSH_DIAGNOSTIC_USER }), true, env);
  if (response.exitCode !== 0) throw sshError('ssh_helper_failed', 'response', 'unknown', 'Remote helper failed. Check Python 3 availability, permissions and operation status before retrying.');
  let data;
  try { data = JSON.parse(response.stdout); } catch { throw sshError('ssh_helper_invalid_response', 'response', 'unknown', 'Incomplete result; check operation status before retrying.'); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw sshError('ssh_helper_invalid_response', 'response', 'unknown', 'Invalid helper result; check operation status before retrying.');
  if (data.error) {
    const error = new Error(data.error);
    error.code = data.code;
    error.details = data.details;
    throw error;
  }
  return data;
}

export function operationId(requestId, env = process.env) {
  if (env.__jump) return crypto.createHash('sha256').update('via\0' + operationId(requestId, { ...env, __jump: undefined }) + '\0' + operationId('route', env.__jump)).digest('hex').slice(0, 32);
  return crypto.createHash('sha256').update([env.SSH_HOST?.trim().toLowerCase(), String(Number(env.SSH_PORT || 22)), env.SSH_USERNAME, requestId].join('\0')).digest('hex').slice(0, 32);
}
