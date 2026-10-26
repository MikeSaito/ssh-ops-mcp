import { readSecureFile } from './file-security.js';

export const toolNames = Object.freeze([
  'ssh_exec', 'ssh_server_info', 'ssh_operation_start', 'ssh_operation_status', 'ssh_operation_report',
  'ssh_operation_logs', 'ssh_operation_list', 'ssh_operation_cancel', 'ssh_deploy_lock_status', 'ssh_deploy_unlock',
  'ssh_file_hash', 'ssh_read_file', 'ssh_file_preview', 'ssh_write_file', 'ssh_upload_file',
  'ssh_download_file', 'ssh_download_status', 'ssh_download_resume', 'ssh_download_pause', 'ssh_download_list',
  'ssh_download_cleanup', 'ssh_download_decrypt', 'ssh_network_probe', 'ssh_service_status', 'ssh_journal_tail',
  'ssh_secret_presence', 'ssh_state_usage', 'ssh_state_cleanup', 'ssh_find_files', 'ssh_search_text', 'ssh_edit_file',
]);
const known = new Set(toolNames), id = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export async function loadPolicy(file) {
  if (!file) return null;
  let value;
  try { value = JSON.parse((await readSecureFile(file, { confidential: false })).toString('utf8')); }
  catch (error) { throw new Error('Cannot load access policy: ' + (error instanceof SyntaxError ? 'invalid JSON.' : error.message)); }
  return parsePolicy(value);
}
export function parsePolicy(value) {
  if (!value || value.version !== 1 || !value.servers || Array.isArray(value.servers) || typeof value.servers !== 'object' || Object.keys(value).some(key => !['version', 'servers', 'transit_servers'].includes(key))) throw new Error('Policy requires version: 1 and a servers object.');
  const servers = new Map();
  for (const [name, entry] of Object.entries(value.servers)) {
    if (!id.test(name) || !entry || Object.keys(entry).some(key => key !== 'tools') || !Array.isArray(entry.tools) || !entry.tools.length || entry.tools.some(tool => !known.has(tool)) || new Set(entry.tools).size !== entry.tools.length) throw new Error('Policy contains an invalid server or tool allow-list.');
    servers.set(name, new Set(entry.tools));
  }
  const transit = value.transit_servers ?? [];
  if (!servers.size || !Array.isArray(transit) || transit.some(name => typeof name !== 'string' || !id.test(name)) || new Set(transit).size !== transit.length) throw new Error('Policy requires at least one target and valid transit_servers.');
  return { servers, transit: new Set(transit) };
}
export function permits(policy, server, tool) { return !policy || policy.servers.get(server)?.has(tool) === true; }
export function validatePolicyTargets(policy, names) {
  if (!policy) return;
  for (const name of [...policy.servers.keys(), ...policy.transit]) if (!names.has(name)) throw new Error('Policy references an unknown server ID.');
}
