import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { exec, withSftp } from './ssh.js';
import { rpc, operationId } from './remote.js';
import { redact, audit, transferPath, sha256 } from './security.js';
import { localLock, atomicJson, readJson } from './local-state.js';
import { Downloads } from './downloads.js';
import { stateDirectory } from './config.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const stateDir = stateDirectory();
const downloads = new Downloads(stateDir);
// Retention applies while MCP is running and again on the next startup, not while it is off.
await downloads.cleanupExpired();
setInterval(() => downloads.cleanupExpired().catch(() => {}), 60000).unref();
const idSchema = z.string().regex(/^[a-f0-9]{32}$/);
const remotePath = z.string().startsWith('/').max(4096);
const expectedHash = z.string().regex(/^[a-f0-9]{64}$/).nullable()
  .describe('Current SHA-256 from ssh_file_hash; null means file must not exist.');
const modeSchema = z.string().regex(/^[0-7]{3,4}$/).optional();
const server = new McpServer({ name: 'ssh-ops-mcp', version: '1.1.0' }, {
  instructions: 'Use ssh_operation_start for deploys, migrations and long work. Always set resource to the same app name or absolute deployment directory across chats to exclude concurrent deploys. Retain request_id/operation_id and poll status/logs after disconnection. Never repeat unknown modifying work. Timeout/cancel terminate the operation process group; disconnection does not. Before editing, hash and preview, then apply with expected_sha256. Use ssh_download_file then status/resume with transfer_id for large files. Enable encrypt for sensitive dumps. Tools have only the configured SSH account privileges; ADMIN is a warning, not a security boundary. Diagnostics never run as root. Keep secrets out of commands and output.',
});

function sanitize(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)]));
  return value;
}
const result = (value) => ({ content: [{ type: 'text', text: typeof value === 'string' ? redact(value) : JSON.stringify(sanitize(value), null, 2) }] });
async function record(entry) { await audit(stateDir, entry); }
function tool(name, description, inputSchema, callback, readOnly = false) {
  server.registerTool(name, {
    description, inputSchema,
    annotations: { readOnlyHint: readOnly, destructiveHint: !readOnly, openWorldHint: true },
  }, async (args) => {
    try {
      // Fail before an action if the audit sink isn't writable.
      await record({ tool: name, operation_id: args.operation_id, outcome: 'requested' });
      const value = await callback(args);
      await record({ tool: name, operation_id: value?.operation_id || args.operation_id, outcome: 'returned' });
      return result(value);
    } catch (error) {
      try { await record({ tool: name, operation_id: args.operation_id, outcome: 'error_or_unknown' }); } catch {}
      const failure = error.details ? result({ error: 'SSH MCP: ' + error.message, code: error.code, details: error.details }) : result('SSH MCP: ' + error.message);
      return { ...failure, isError: true };
    }
  });
}
function deadline(value) {
  const parsed = Number(value ?? process.env.SSH_COMMAND_TIMEOUT_MS ?? 60_000);
  return Number.isFinite(parsed) ? Math.max(1000, Math.min(parsed, 1_800_000)) : 60_000;
}

tool('ssh_exec', 'ADMIN: synchronous arbitrary shell command with the configured SSH account privileges. For modifying or long commands use ssh_operation_start. On disconnect/timeout outcome is unknown; never retry automatically.', {
  command: z.string().min(1).max(1_000_000), timeout_ms: z.number().int().min(1000).max(1_800_000).optional(),
}, ({ command, timeout_ms }) => exec(command, deadline(timeout_ms)));

tool('ssh_server_info', 'Basic server identification and health. Returns the existing text command result.', {},
  () => exec('hostname; uname -a; uptime; id', 30_000), true);

tool('ssh_operation_start', 'ADMIN: start a persistent background operation. Same request_id and options never rerun the command. Save the returned operation_id even on error. SSH/MCP disconnection does not stop work; deadline/cancel kill its process group.', {
  request_id: z.string().min(1).max(200).describe('Stable unique name reused after uncertain connection; use a new name only for intentionally new work.'),
  command: z.string().min(1).max(1_000_000).optional().describe('Use either command or steps, never both.'),
  title: z.string().min(1).max(200).optional().describe('Short non-secret task title for reports, locks and history. Defaults to request_id.'),
  steps: z.array(z.object({ name: z.string().min(1).max(200), command: z.string().min(1).max(1_000_000) })).min(1).max(20).optional().describe('Named phases in order. Each runs in a fresh bash shell; failure stops later phases. One deadline covers all phases.'),
  timeout_seconds: z.number().int().min(1).max(86400).default(3600),
  resource: z.string().min(1).max(200).optional().describe('Shared app name or absolute deployment directory; every chat must use the same resource for this app. Prevents different request IDs from deploying concurrently.'),
}, async (args) => {
  if ((args.command === undefined) === (args.steps === undefined)) throw new Error('Provide exactly one of command or steps.');
  if (args.steps && args.steps.reduce((bytes, step) => bytes + step.command.length, 0) > 1_000_000) throw new Error('Combined step commands exceed 1 MiB.');
  const operation_id = operationId(args.request_id);
  const spec = { ...(args.steps ? { steps: args.steps } : { command: args.command }), timeout_seconds: args.timeout_seconds, ...(args.resource ? { resource: args.resource } : {}) };
  const specHash = sha256(JSON.stringify(spec));
  await fs.mkdir(stateDir, { recursive: true });
  const manifest = path.join(stateDir, operation_id + '.json');
  const metadata = JSON.stringify({ operation_id, spec_hash: specHash, server: process.env.SSH_HOST, created_at: new Date().toISOString() });
  await localLock(manifest + '.lock', async () => {
    const old = await readJson(manifest).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (old && old.spec_hash !== specHash) throw new Error('request_id already used with other command/options.');
    if (!old) await atomicJson(manifest, JSON.parse(metadata));
  });
  try { return await rpc('start', { operation_id, ...spec, request_id: redact(args.request_id), ...(args.title ? { title: redact(args.title) } : {}) }); }
  catch (error) {
    if (error.code === 'resource_busy') throw error; // Explicit pre-launch rejection, not an unknown launch.
    throw new Error('operation_id=' + operation_id + '. Launch outcome unknown: ' + error.message + '. Poll ssh_operation_status or repeat the same request_id and exact options; do not use a new request_id.');
  }
});

tool('ssh_operation_status', 'Read persisted operation state. connection_lost/unknown is not a stopped operation.', {
  operation_id: idSchema,
}, async (args) => {
  try { return await rpc('status', args); }
  catch (error) { return { operation_id: args.operation_id, state: 'connection_lost_or_unavailable', outcome: 'unknown', detail: redact(error.message) }; }
}, true);

tool('ssh_operation_report', 'Unified operation report: safe task title, named phases, UTC times, queue/execution duration, exit code and outcome. Legacy operations may have partial timing. No commands or log contents are included.', {
  operation_id: idSchema,
}, args => rpc('report', args), true);

tool('ssh_operation_logs', 'Read redacted bounded operation logs incrementally. Reuse next_offset for the same stream. Cursor counts bytes in the redacted view; logs remain after reconnect/restart.', {
  operation_id: idSchema, stream: z.enum(['stdout', 'stderr']).default('stdout'),
  offset: z.number().int().min(0).default(0), limit_bytes: z.number().int().min(1).max(65536).default(16384),
}, (args) => rpc('logs', args), true);

tool('ssh_operation_list', 'Search history by non-secret title/request ID/operation ID/resource; filter states, exact resource and creation time. Newest first, stable cursor pagination. Commands/log contents are never searched. Reuse next_cursor with identical filters.', {
  query: z.string().max(200).optional(),
  states: z.array(z.enum(['starting', 'running', 'completed', 'failed', 'timed_out', 'cancelled', 'process_lost'])).min(1).max(7).optional(),
  resource: z.string().min(1).max(200).optional(),
  created_after: z.string().datetime({ offset: true }).optional(),
  created_before: z.string().datetime({ offset: true }).optional(),
  limit: z.number().int().min(1).max(100).default(100),
  cursor: z.string().max(2048).optional(),
}, args => rpc('list', args), true);
tool('ssh_operation_cancel', 'ADMIN: request cancellation of a background operation and its process group. Poll status to confirm; it cannot roll back changes already made.', {
  operation_id: idSchema,
}, (args) => rpc('cancel', args));

tool('ssh_deploy_lock_status', 'Explain which task holds a resource: title, request/operation ID, current phase, elapsed time and recovery advice. process_lost stays blocked until verified.', {
  resource: z.string().min(1).max(200),
}, args => rpc('resource_status', args), true);
tool('ssh_deploy_unlock', 'ADMIN: explicitly release an abandoned resource only after verifying processes/effects. Cannot unlock starting/running work. Not a rollback.', {
  resource: z.string().min(1).max(200), expected_operation_id: idSchema,
  verified_stopped: z.boolean().default(false),
}, args => rpc('resource_unlock', args));

tool('ssh_file_hash', 'Return file SHA-256 and permission metadata without contents. Refuses symlink targets.', {
  path: remotePath,
}, (args) => rpc('file_hash', args), true);

tool('ssh_read_file', 'Read a bounded range of lines, redacting common secret patterns. Do not request secret files when ssh_secret_presence suffices.', {
  path: remotePath, start_line: z.number().int().min(1).default(1),
  lines: z.number().int().min(1).max(2000).default(200),
}, (args) => rpc('read', args), true);

tool('ssh_file_preview', 'Show a redacted diff without modifying the target. Requires the current hash, or null for a new file.', {
  path: remotePath, content: z.string().max(5_000_000), expected_sha256: expectedHash,
}, (args) => rpc('write', { ...args, preview: true }), true);

tool('ssh_write_file', 'ADMIN: atomically replace text after comparing expected_sha256. Existing owner/mode are retained; backup is private. Optional staged validator must contain {path}. On uncertain reply inspect the hash before retrying.', {
  path: remotePath, content: z.string().max(5_000_000), expected_sha256: expectedHash,
  mode: modeSchema.describe('Mode for a new file only; existing permissions are preserved.'),
  backup: z.boolean().default(true),
  validate_command: z.string().max(10000).optional().describe('Validator command containing {path}, replaced with shell-quoted staged path; never use the live path.'),
}, (args) => rpc('write', args, 45_000));

tool('ssh_upload_file', 'ADMIN: SFTP binary upload staged privately then atomically installed after expected hash comparison. Local source must be under transfers/. Existing owner/mode are preserved.', {
  local_path: z.string().min(1), remote_path: remotePath, expected_sha256: expectedHash, mode: modeSchema,
}, async ({ local_path, remote_path, expected_sha256, mode }) => {
  const source = await transferPath(ROOT, local_path);
  if (!(await fs.stat(source)).isFile()) throw new Error('Source must be a regular file.');
  const upload_id = crypto.randomBytes(16).toString('hex');
  const staged = await rpc('upload_prepare', { upload_id });
  await withSftp((sftp) => new Promise((resolve, reject) => {
    sftp.fastPut(source, staged.path, { mode: 0o600 }, (error) => error ? reject(error) : resolve());
  }));
  return rpc('upload_commit', { upload_id, path: remote_path, expected_sha256, mode }, 60_000);
});

tool('ssh_download_file', 'Start private background download; returns transfer_id and progress, not contents. Poll status, resume same ID after interruption. Stable remote identity and SHA-256 are verified. Optional encryption is AES-256-GCM with a DPAPI-protected key on Windows.', {
  remote_path: remotePath, local_path: z.string().min(1), overwrite: z.boolean().default(false),
  encrypt: z.boolean().default(false), retention_days: z.number().int().min(1).max(365).default(7),
  wait_ms: z.number().int().min(0).max(20000).default(1000),
}, async args => { const started = await downloads.start(args); return downloads.wait(started.transfer_id, args.wait_ms); });
tool('ssh_download_status', 'Read byte progress and integrity state; no file content.', { transfer_id: idSchema },
  args => downloads.status(args.transfer_id), true);
tool('ssh_download_resume', 'Resume same download ID from committed bytes. Refuses changed remote source or invalid encrypted frames; never blindly restarts.', { transfer_id: idSchema },
  args => downloads.resume(args.transfer_id));
tool('ssh_download_pause', 'Pause a background download, retaining committed bytes for resume. Poll status to confirm.', { transfer_id: idSchema },
  args => downloads.pause(args.transfer_id));
tool('ssh_download_list', 'Find the last 100 local transfers after MCP restart.', {}, () => downloads.list(), true);
tool('ssh_download_cleanup', 'DELETE local downloaded data and key for this exact transfer. By default only expired data; explicit expired_only=false permits early deletion. Cannot delete running work.', {
  transfer_id: idSchema, expired_only: z.boolean().default(true),
}, args => downloads.cleanup(args.transfer_id, args.expired_only));
tool('ssh_download_decrypt', 'EXPLICIT plaintext export of an encrypted completed download to private transfers/. Verifies authenticated frames and SHA-256, refuses overwrite. Never displays contents. Export is not deleted by transfer cleanup.', {
  transfer_id: idSchema, local_path: z.string().min(1),
}, args => downloads.decrypt(args.transfer_id, args.local_path));

tool('ssh_network_probe', 'Unprivileged DNS, TCP, verified TLS, SMTP greeting or STARTTLS probe. Reports each stage; does not send mail or credentials.', {
  host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535),
  protocol: z.enum(['tcp', 'tls', 'smtp', 'smtp_starttls']).default('tcp'),
  timeout_seconds: z.number().int().min(1).max(10).default(5),
}, (args) => rpc('probe', args, 60_000), true);

tool('ssh_service_status', 'Unprivileged systemd service state; diagnostics account has no sudo.', {
  name: z.string().regex(/^[A-Za-z0-9_.@-]+$/).max(200),
}, (args) => rpc('service', args), true);

tool('ssh_journal_tail', 'ADMIN READ: bounded last journal lines for one service, with secret redaction.', {
  service: z.string().regex(/^[A-Za-z0-9_.@-]+$/).max(200),
  lines: z.number().int().min(1).max(1000).default(100),
}, (args) => rpc('journal', args), true);

tool('ssh_secret_presence', 'ADMIN READ: report whether named variables in an env file are nonempty. Returns no values or hashes.', {
  path: remotePath, names: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)).min(1).max(100),
}, (args) => rpc('secret_presence', args), true);

await server.connect(new StdioServerTransport());
