#!/usr/bin/env node
import { loadEnvironment, buildConnectOptions } from '../src/config.js';
import { redact } from '../src/security.js';

const args = process.argv.slice(2);
let envFile, check = false;
try {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') {
      console.log('SSH Ops MCP 1.1.0\nUsage: node bin/ssh-ops-mcp.js [--env-file /private/server.env] [--check-config]\nAuthentication: password, private_key (optional passphrase), agent.\n--check-config validates locally without contacting a server or printing credentials.');
      process.exit(0);
    } else if (args[i] === '--version') { console.log('1.1.0'); process.exit(0); }
    else if (args[i] === '--check-config') check = true;
    else if (args[i] === '--env-file' && args[i + 1] && !args[i + 1].startsWith('--') && !envFile) envFile = args[++i];
    else throw new Error('Unknown or incomplete option. Use --help.');
  }
  await loadEnvironment(envFile);
  const options = await buildConnectOptions();
  if (check) {
    console.log(JSON.stringify({ valid: true, auth_method: process.env.SSH_AUTH_METHOD, host_key_verification: Boolean(process.env.SSH_HOST_FINGERPRINT_SHA256), agent_forwarding: options.agentForward }));
  } else {
    if (!process.env.SSH_HOST_FINGERPRINT_SHA256) console.error('WARNING: SSH host identity verification explicitly disabled. Development only.');
    await import('../src/index.js');
  }
} catch (error) { console.error(redact('SSH Ops MCP: ' + error.message)); process.exitCode = 1; }
