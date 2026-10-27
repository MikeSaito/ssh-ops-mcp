import fs from 'node:fs/promises';
import path from 'node:path';
import { constants } from 'node:fs';
import { exec, quote, withSftp } from './ssh.js';
import { permits } from './policy.js';
import { checkStateDirectory } from './file-security.js';

export async function doctor(registry, { connect = false, serverId } = {}) {
  const checks = [], [major, minor] = process.versions.node.split('.').map(Number);
  checks.push({ name: 'node', ok: major > 22 || (major === 22 && minor >= 13), version: process.versions.node });
  try { await import('node:sqlite'); checks.push({ name: 'sqlite', ok: true }); } catch { checks.push({ name: 'sqlite', ok: false }); }
  for (const profile of registry.profiles.values()) {
    try {
      const exists = await checkStateDirectory(profile.stateDir);
      checks.push({ name: 'local_state_permissions', server_id: profile.id, ok: true, exists });
    } catch {
      checks.push({ name: 'local_state_permissions', server_id: profile.id, ok: false });
    }
    let dir = profile.stateDir;
    while (!await fs.stat(dir).then(item => item.isDirectory(), () => false)) {
      const parent = path.dirname(dir); if (parent === dir) break; dir = parent;
    }
    checks.push({ name: 'local_state_parent_writable', server_id: profile.id, ok: await fs.access(dir, constants.W_OK).then(() => true, () => false) });
    checks.push({ name: 'configuration_and_file_permissions', server_id: profile.id, ok: true,
      auth_method: profile.env.SSH_AUTH_METHOD, host_key_verification: Boolean(profile.env.SSH_HOST_FINGERPRINT_SHA256), via: Boolean(profile.env.__jump) });
    if (!profile.env.SSH_HOST_FINGERPRINT_SHA256 || (profile.env.__jump && !profile.env.__jump.SSH_HOST_FINGERPRINT_SHA256))
      checks.push({ name: 'host_key_verification', server_id: profile.id, ok: false, required: false, warning: 'A configured connection does not verify the host key.' });
  }
  if (connect) {
    const selected = registry.profiles.get(serverId ?? (registry.multi ? undefined : 'default'));
    if (!selected || !permits(registry.policy, selected.id, 'ssh_server_info')) throw new Error('Select an allowed server with ssh_server_info permission for the connection probe.');
    const probe = "import json,sys,platform,shutil,importlib.util;print(json.dumps({'linux':platform.system()=='Linux','python_ok':sys.version_info>=(3,8),'bash':bool(shutil.which('bash')),'sqlite':importlib.util.find_spec('_sqlite3') is not None}))";
    try {
      const result = await exec('python3 -B -c ' + quote(probe), 15000, '', true, selected.env);
      const value = JSON.parse(result.stdout);
      for (const name of ['linux', 'python_ok', 'bash', 'sqlite']) checks.push({ name: 'remote_' + name, server_id: selected.id, ok: result.exitCode === 0 && value[name] === true, required: name !== 'sqlite' });
      await withSftp(async () => {}, 15000, selected.env);
      checks.push({ name: 'sftp', server_id: selected.id, ok: true });
    } catch (error) { checks.push({ name: 'connection_probe', server_id: selected.id, ok: false, code: error.code || 'probe_failed' }); }
  }
  return { ready: checks.every(check => check.ok || check.required === false), network_requested: connect, checks };
}
