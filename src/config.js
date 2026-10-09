import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import ssh2 from 'ssh2';
import { fileURLToPath } from 'node:url';
import { registerSecret } from './security.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const { utils } = ssh2;
export async function loadEnvironment(envFile) {
  const file = envFile ? path.resolve(envFile) : path.join(ROOT, '.env');
  let bytes;
  try { bytes = await fs.readFile(file, 'utf8'); }
  catch (error) { if (!envFile && error.code === 'ENOENT') return; throw new Error('Cannot read the selected environment file.'); }
  const parsed = dotenv.parse(bytes);
  // Explicit process environment takes precedence; never search a parent project.
  for (const [key, value] of Object.entries(parsed)) if (process.env[key] === undefined) process.env[key] = value;
  process.env.SSH_MCP_CONFIG_DIR = path.dirname(file);
}
function resolveFile(value, env) {
  const expanded = value.startsWith('~/') || value.startsWith('~\\') ? path.join(os.homedir(), value.slice(2)) : value;
  return path.resolve(env.SSH_MCP_CONFIG_DIR || process.cwd(), expanded);
}
async function readPrivateFile(value, env) {
  const file = resolveFile(value, env);
  // Limit input, reject symlinks and public POSIX permissions. Windows users must protect the file ACL.
  const info = await fs.lstat(file).catch(() => { throw new Error('Cannot read credential file.'); });
  if (!info.isFile() || info.size > 1024 * 1024) throw new Error('Credential file must be a regular file smaller than 1 MiB.');
  if (process.platform !== 'win32' && (info.mode & 0o077)) throw new Error('Credential file permissions must be 0600 or stricter.');
  return fs.readFile(file);
}
async function secret(env, name) {
  if (env[name] && env[name + '_FILE']) throw new Error(`Set either ${name} or ${name}_FILE, not both.`);
  const value = env[name + '_FILE'] ? (await readPrivateFile(env[name + '_FILE'], env)).toString('utf8').replace(/\r?\n$/, '') : env[name];
  if (value) registerSecret(value);
  return value;
}
export function connectionIdentity(env = process.env) {
  return crypto.createHash('sha256').update([env.SSH_HOST?.trim().toLowerCase(), String(Number(env.SSH_PORT || 22)), env.SSH_USERNAME].join('\0')).digest('hex').slice(0, 24);
}
export function stateDirectory(env = process.env) {
  const base = env.SSH_MCP_STATE_DIR ? path.resolve(env.SSH_MCP_STATE_DIR) : path.join(os.homedir(), '.ssh-ops-mcp', 'state');
  return path.join(base, connectionIdentity(env));
}
export async function buildConnectOptions(env = process.env) {
  const host = env.SSH_HOST?.trim();
  const username = env.SSH_USERNAME;
  const port = Number(env.SSH_PORT || 22);
  if (!host || /[\s/\\\x00]/.test(host)) throw new Error('SSH_HOST must be an IP address or hostname, not an URL.');
  if (!username || /[\s\x00]/.test(username)) throw new Error('SSH_USERNAME is required; root is never selected implicitly.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SSH_PORT must be between 1 and 65535.');
  const method = env.SSH_AUTH_METHOD;
  if (!['password', 'private_key', 'agent'].includes(method)) throw new Error('SSH_AUTH_METHOD must be password, private_key or agent.');
  const insecure = env.SSH_ALLOW_UNVERIFIED_HOST === 'true';
  if (env.SSH_ALLOW_UNVERIFIED_HOST && !['true', 'false'].includes(env.SSH_ALLOW_UNVERIFIED_HOST)) throw new Error('SSH_ALLOW_UNVERIFIED_HOST must be true or false.');
  const fingerprint = env.SSH_HOST_FINGERPRINT_SHA256?.replace(/^SHA256:/, '').replace(/=+$/, '');
  if (!fingerprint && !insecure) throw new Error('SSH_HOST_FINGERPRINT_SHA256 is required. Obtain it through a trusted channel; never auto-trust a scanned key.');
  if (fingerprint && (!/^[A-Za-z0-9+/]{43}$/.test(fingerprint) || Buffer.from(fingerprint, 'base64').length !== 32 || Buffer.from(fingerprint, 'base64').toString('base64').replace(/=+$/, '') !== fingerprint)) throw new Error('Invalid SHA256 host fingerprint.');
  const options = {
    host, port, username, readyTimeout: 30_000, keepaliveInterval: 15_000, keepaliveCountMax: 3,
    agentForward: false, tryKeyboard: false,
    hostVerifier: fingerprint ? key => crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '') === fingerprint : () => true,
  };
  if (method === 'password') {
    options.password = await secret(env, 'SSH_PASSWORD');
    if (!options.password) throw new Error('Password authentication requires SSH_PASSWORD or SSH_PASSWORD_FILE.');
    options.authHandler = ['password'];
  } else if (method === 'private_key') {
    if (!env.SSH_PRIVATE_KEY_PATH) throw new Error('Private-key authentication requires SSH_PRIVATE_KEY_PATH.');
    options.privateKey = await readPrivateFile(env.SSH_PRIVATE_KEY_PATH, env);
    registerSecret(options.privateKey.toString('utf8'));
    options.passphrase = await secret(env, 'SSH_KEY_PASSPHRASE');
    const parsed = utils.parseKey(options.privateKey, options.passphrase);
    if (parsed instanceof Error || (Array.isArray(parsed) ? parsed.some(key => !key.isPrivateKey()) : !parsed.isPrivateKey())) throw new Error('Invalid private key or passphrase, or unsupported key format. Use an OpenSSH/PEM private key, not a .pub or PuTTY .ppk file.');
    options.authHandler = ['publickey'];
  } else {
    options.agent = env.SSH_AGENT_SOCKET || env.SSH_AUTH_SOCK || (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : undefined);
    if (!options.agent) throw new Error('Agent authentication requires SSH_AGENT_SOCKET or SSH_AUTH_SOCK.');
    options.authHandler = ['agent'];
  }
  return options;
}
