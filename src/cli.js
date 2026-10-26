import path from 'node:path';
import { loadEnvironment, loadRegistry, buildConnectOptions } from './config.js';
import { loadPolicy, validatePolicyTargets } from './policy.js';
import { redact } from './security.js';
import { packageInfo } from './version.js';

export async function runCli(args = process.argv.slice(2), launch) {
  let envFile, serversFile = process.env.SSH_MCP_SERVERS_FILE, policyFile = process.env.SSH_MCP_POLICY_FILE;
  let check = false, diagnose = false, connect = false, serverId, printConfig = false;
  try {
    const values = new Map();
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '--help' || arg === '-h') {
        console.log(packageInfo.name + ' ' + packageInfo.version + '\nOptions: --connection-file FILE | --servers-file FILE; --policy-file FILE; --check-config; --doctor [--connect --server-id ID]; --print-client-config; --version\nLegacy --env-file requires node -- ENTRY to avoid Node native env-file handling. Config/doctor checks are local unless --connect is explicit. No credentials are printed.'); return;
      }
      if (arg === '--version') { console.log(packageInfo.version); return; }
      if (['--env-file', '--connection-file', '--servers-file', '--policy-file', '--server-id'].includes(arg)) {
        if (values.has(arg) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Duplicate or incomplete option. Use --help.');
        values.set(arg, args[++i]);
      } else if (arg === '--check-config') check = true;
      else if (arg === '--doctor') diagnose = true;
      else if (arg === '--connect') connect = true;
      else if (arg === '--print-client-config') printConfig = true;
      else throw new Error('Unknown option. Use --help.');
    }
    if (values.has('--env-file') && values.has('--connection-file')) throw new Error('Use only one connection-file option.');
    envFile = values.get('--connection-file') || values.get('--env-file'); serversFile = values.get('--servers-file') || serversFile;
    policyFile = values.get('--policy-file') || policyFile; serverId = values.get('--server-id');
    if (serversFile && envFile) throw new Error('--servers-file and --env-file cannot be combined.');
    if ((connect && !diagnose) || (serverId && !connect) || (diagnose && check)) throw new Error('Use --doctor --connect --server-id ID for an explicit network probe.');
    if (printConfig) {
      if (check || diagnose || connect) throw new Error('Print configuration separately from checks.');
      const launchArgs = ['--', path.resolve(process.argv[1])];
      for (const [flag, value] of [['--connection-file', envFile], ['--servers-file', serversFile], ['--policy-file', policyFile]]) if (value) launchArgs.push(flag, path.resolve(value));
      console.log(JSON.stringify({ mcpServers: { ssh_ops: { command: process.execPath, args: launchArgs } } }, null, 2)); return;
    }
    const policy = await loadPolicy(policyFile);
    if (!serversFile) { validatePolicyTargets(policy, new Set(['default'])); await loadEnvironment(envFile); }
    const registry = await loadRegistry({ serversFile, policyFile });
    if (!registry.multi) await buildConnectOptions();
    if (diagnose) {
      const { doctor } = await import('./doctor.js');
      const report = await doctor(registry, { connect, serverId });
      console.log(JSON.stringify(report)); if (!report.ready) process.exitCode = 1; return;
    }
    if (check) {
      console.log(JSON.stringify({ valid: true, multi_server: registry.multi, policy_applied: Boolean(registry.policy),
        ...(!registry.multi ? { auth_method: process.env.SSH_AUTH_METHOD, host_key_verification: Boolean(process.env.SSH_HOST_FINGERPRINT_SHA256), agent_forwarding: false } : {}),
        servers: [...registry.profiles.values()].map(profile => ({ server_id: profile.id, valid: true, auth_method: profile.env.SSH_AUTH_METHOD, host_key_verification: Boolean(profile.env.SSH_HOST_FINGERPRINT_SHA256), agent_forwarding: false })) })); return;
    }
    for (const profile of registry.profiles.values()) if (!profile.env.SSH_HOST_FINGERPRINT_SHA256) console.error('WARNING: SSH host verification disabled; not suitable for production.');
    const start = launch || (await import('./index.js')).start;
    return await start(registry);
  } catch (error) {
    const message = 'SSH MCP: ' + redact(error.message);
    if (diagnose) console.log(JSON.stringify({ ready: false, network_requested: connect, checks: [{ name: 'configuration', ok: false, error: message }] }));
    else console.error(message);
    process.exitCode = 1;
  }
}
