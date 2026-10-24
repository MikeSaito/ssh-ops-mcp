import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { loadEnvironment, loadRegistry, describeProfile, serverIdPattern } from './config.js';
import { createTools } from './tools.js';
import { Downloads } from './downloads.js';
import { redact, audit } from './security.js';
import { auditedCall } from './audited-call.js';
import { packageInfo } from './version.js';

function sanitize(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)]));
  return value;
}
const result = value => ({ content: [{ type: 'text', text: typeof value === 'string' ? redact(value) : JSON.stringify(sanitize(value), null, 2) }] });
const tagged = (registry, profile, value) => registry.multi ? { ...(value && typeof value === 'object' && !Array.isArray(value) ? value : { result: value }), server_id: profile.id } : value;

export async function start(registry) {
  const server = new McpServer(packageInfo, {
    instructions: 'Call ssh_servers_list to discover profiles. In multi-server mode every action requires explicit server_id; there is no active server. Keep the same server_id when polling operations or transfers. Use ssh_operation_start for deploys, migrations and long work. Always set resource to the same app name or absolute deployment directory across chats to exclude concurrent deploys. Retain request_id/operation_id and poll status/logs after disconnection. Never repeat unknown modifying work. Timeout/cancel terminate the operation process group; disconnection does not. Before editing, hash and preview, then apply with expected_sha256. Use ssh_download_file then status/resume with transfer_id for large files. Enable encrypt for sensitive dumps. Tools have only the configured SSH account privileges; ADMIN is a warning, not a security boundary. Diagnostics never run as root. Keep secrets out of commands and output.',
  });
  const contexts = new Map([...registry.profiles].map(([id, profile]) => {
    const context = { ...profile, downloads: new Downloads(profile.stateDir, profile.env, registry.multi) };
    return [id, { ...context, definitions: new Map(createTools(context).map(def => [def.name, def])) }];
  }));
  await Promise.allSettled([...contexts.values()].map(context => context.downloads.cleanupExpired()));
  const cleanup = setInterval(() => Promise.allSettled([...contexts.values()].map(context => context.downloads.cleanupExpired())), 60000);
  cleanup.unref();
  const template = contexts.values().next().value;
  for (const def of template.definitions.values()) {
    const selector = z.string().regex(serverIdPattern).describe('Server ID from ssh_servers_list. No automatic fallback.');
    server.registerTool(def.name, {
      description: def.description,
      inputSchema: { ...def.inputSchema, server_id: registry.multi ? selector : selector.optional() },
      annotations: { readOnlyHint: def.readOnly, destructiveHint: !def.readOnly, openWorldHint: true },
    }, async args => {
      let context;
      let warnings = [];
      const { server_id, ...input } = args;
      try {
        context = contexts.get(server_id ?? (registry.multi ? undefined : 'default'));
        if (!context) throw new Error('Unknown or missing server_id. Use ssh_servers_list.');
        const record = entry => audit(context.stateDir, { ...entry, server: context.env.SSH_HOST, ...(registry.multi ? { server_id: context.id } : {}) });
        const call = await auditedCall(record, { tool: def.name, operation_id: input.operation_id }, () => context.definitions.get(def.name).callback(input));
        warnings = call.warnings;
        if (call.error) throw call.error;
        const response = result(tagged(registry, context, call.value));
        for (const warning of warnings) response.content.push(...result(tagged(registry, context, warning)).content);
        return response;
      } catch (error) {
        const value = error.details ? { error: 'SSH MCP: ' + error.message, code: error.code, details: error.details } : registry.multi ? { error: 'SSH MCP: ' + error.message } : 'SSH MCP: ' + error.message;
        if (registry.multi && error.transport) Object.assign(value, { code: error.code, connection: error.transport, ...(error.operation_id ? { operation_id: error.operation_id } : {}) });
        const failure = registry.multi ? { ...(typeof value === 'object' ? value : { error: value }), server_id: context?.id ?? server_id ?? null } : value;
        const response = { ...result(failure), isError: true };
        for (const warning of warnings) response.content.push(...result(tagged(registry, context, warning)).content);
        return response;
      }
    });
  }
  server.registerTool('ssh_servers_list', {
    description: 'List configured server IDs and non-secret connection metadata. No network requests, credentials or credential paths.',
    inputSchema: {}, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, () => result({ multi_server: registry.multi, servers: [...registry.profiles.values()].map(describeProfile) }));
  try { await server.connect(new StdioServerTransport()); }
  catch (error) { clearInterval(cleanup); throw error; }
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (!process.env.SSH_MCP_SERVERS_FILE) await loadEnvironment();
    await start(await loadRegistry({ serversFile: process.env.SSH_MCP_SERVERS_FILE }));
  } catch (error) { console.error(redact('SSH MCP: ' + error.message)); process.exitCode = 1; }
}
