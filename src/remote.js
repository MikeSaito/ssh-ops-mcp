import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { exec, quote } from './ssh.js';

const source = await fs.readFile(fileURLToPath(new URL('./remote_helper.py', import.meta.url)), 'utf8');

export async function rpc(action, args = {}, timeoutMs = 30_000) {
  const bootstrap = 'import json,sys; p=json.loads(sys.stdin.read()); exec(compile(p["source"],"mcp-helper","exec"))';
  // Source and payload use stdin; command content is never argv or an action log.
  const response = await exec('python3 -c ' + quote(bootstrap), timeoutMs, JSON.stringify({ source, action, args, diagnostic_user: process.env.SSH_DIAGNOSTIC_USER }), true);
  if (response.exitCode !== 0) throw new Error('Remote helper failed. Check Python 3 availability and permissions.');
  let data;
  try { data = JSON.parse(response.stdout); } catch { throw new Error('Incomplete result; check operation status before retrying.'); }
  if (data.error) {
    const error = new Error(data.error);
    error.code = data.code;
    error.details = data.details;
    throw error;
  }
  return data;
}

export function operationId(requestId) {
  return crypto.createHash('sha256').update([process.env.SSH_HOST?.trim().toLowerCase(), String(Number(process.env.SSH_PORT || 22)), process.env.SSH_USERNAME, requestId].join('\0')).digest('hex').slice(0, 32);
}
