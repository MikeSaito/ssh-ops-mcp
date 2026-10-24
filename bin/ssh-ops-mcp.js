#!/usr/bin/env node
import { loadEnvironment, loadRegistry, buildConnectOptions, describeProfile } from '../src/config.js';
import { redact } from '../src/security.js';
import { packageInfo } from '../src/version.js';

const args = process.argv.slice(2);
let envFile, serversFile, check = false;
try {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') {
      console.log('SSH Ops MCP ' + packageInfo.version + '\nUsage: node bin/ssh-ops-mcp.js [--env-file /private/server.env | --servers-file /private/servers.json] [--check-config]\nAuthentication: password, private_key (optional passphrase), agent.\nMulti-server actions require server_id. Config checks are local and do not display credentials.');
      process.exit(0);
    } else if (args[i] === '--version') { console.log(packageInfo.version); process.exit(0); }
    else if (args[i] === '--check-config') check = true;
    else if (args[i] === '--env-file' && args[i + 1] && !args[i + 1].startsWith('--') && !envFile) envFile = args[++i];
    else if (args[i] === '--servers-file' && args[i + 1] && !args[i + 1].startsWith('--') && !serversFile) serversFile = args[++i];
    else throw new Error('Unknown or incomplete option. Use --help.');
  }
  if (serversFile && envFile) throw new Error('--servers-file and --env-file cannot be combined.');
  if (!serversFile) await loadEnvironment(envFile);
  const registry = await loadRegistry({ serversFile });
  if (!registry.multi) await buildConnectOptions();
  if (check) {
    if (registry.multi) console.log(JSON.stringify({ valid: true, multi_server: true, servers: [...registry.profiles.values()].map(profile => ({ server_id: profile.id, valid: true, auth_method: profile.env.SSH_AUTH_METHOD, host_key_verification: Boolean(profile.env.SSH_HOST_FINGERPRINT_SHA256), agent_forwarding: false })) }));
    else console.log(JSON.stringify({ valid: true, auth_method: process.env.SSH_AUTH_METHOD, host_key_verification: Boolean(process.env.SSH_HOST_FINGERPRINT_SHA256), agent_forwarding: false }));
  } else {
    for (const profile of registry.profiles.values()) if (!profile.env.SSH_HOST_FINGERPRINT_SHA256) console.error('WARNING: SSH host identity verification explicitly disabled. Development only.');
    const { start } = await import('../src/index.js');
    await start(registry);
  }
} catch (error) { console.error(redact('SSH Ops MCP: ' + error.message)); process.exitCode = 1; }
