import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { localLock } from './local-state.js';

const loadedSecrets = new Set();
export function registerSecret(value) { if (value) loadedSecrets.add(String(value)); }
export function redact(value) {
  let text = String(value);
  for (const secret of [...loadedSecrets].sort((a, b) => b.length - a.length)) text = text.split(secret).join('[REDACTED]');
  for (const name of ['SSH_PASSWORD', 'SSH_KEY_PASSPHRASE']) {
    const secret = process.env[name];
    if (secret) text = text.split(secret).join('[REDACTED]');
  }
  text = text.replace(/(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+/gi, '$1[REDACTED]');
  return maskAssignments(text)
    .replace(/-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|$)/g, preserveLines)
    .replace(/(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+/gi, '$1[REDACTED]')
    .replace(/(\w+:\/\/[^\s/:]+:)[^\s@]+@/g, '$1[REDACTED]@');
}

function preserveLines(value) { return value.replace(/[^\r\n]+/g, '[REDACTED]'); }
export function sensitiveKey(key) {
  const normal = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[.-]/g, '_').toLowerCase();
  return /(?:^|_)(?:password|passwd|passphrase|token|secret|api_?key|private_?key|access_?key|secret_?key|credentials?|authorization)(?:_(?:value|data))?$/.test(normal);
}
function maskAssignments(text) {
  // Horizontal whitespace only: an empty YAML value never captures the next key.
  text = text.replace(/((?:"[\w.-]+"|'[\w.-]+'|\b[\w.-]+)[ \t]*[:=][ \t]*)("(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\r\n,;{}\[\]]+)/g,
    (whole, prefix, value) => {
      const key = prefix.match(/^["']?([\w.-]+)/)?.[1];
      if (key?.toLowerCase() === 'authorization' && /^(?:Bearer|Basic)[ \t]+$/.test(value)) return whole;
      const suffix = value.match(/[ \t]*(?:#.*)?$/)[0];
      const scalar = value.slice(0, value.length - suffix.length);
      if (!sensitiveKey(key || '') || !scalar || /^(?:true|false|null|~|[|>][+-]?)$/i.test(scalar)) return whole;
      const quote = value[0];
      if ((quote === '"' || quote === "'") && value.at(-1) === quote)
        return prefix + quote + preserveLines(value.slice(1, -1)) + quote;
      // YAML inline comments are kept by the tokenizer; JSON quotes stay intact.
      return prefix + '[REDACTED]' + suffix;
    });
  const lines = text.split(/(?<=\n)/);
  let blockIndent = null;
  return lines.map(line => {
    const indent = line.match(/^[ \t]*/)[0].length;
    if (blockIndent !== null) {
      if (!line.trim()) return line;
      if (indent > blockIndent) return line.replace(/[^\r\n]+/, chunk => chunk.match(/^[ \t]*/)[0] + '[REDACTED]');
      blockIndent = null;
    }
    const block = line.match(/^[ \t]*["']?([\w.-]+)["']?[ \t]*:[ \t]*[|>][+-]?[ \t]*(?:#.*)?(?:\r?\n)?$/);
    if (block && sensitiveKey(block[1])) blockIndent = indent;
    return line;
  }).join('');
}
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

export async function transferPath(root, relativePath, createParents = false) {
  const base = path.resolve(root, 'transfers');
  const destination = path.resolve(root, relativePath);
  if (!destination.startsWith(base + path.sep)) throw new Error('local_path must be below transfers/ in the MCP project.');
  const segments = path.relative(root, destination).split(path.sep);
  let current = root;
  for (const [index, segment] of segments.entries()) {
    current = path.join(current, segment);
    try {
      if ((await fs.lstat(current)).isSymbolicLink()) throw new Error('Transfer paths cannot contain symlinks or junctions.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (createParents && index < segments.length - 1) await fs.mkdir(current);
    }
  }
  return destination;
}

export async function audit(root, entry) {
  const dir = root;
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const safe = {
    time: new Date().toISOString(), server: process.env.SSH_HOST,
    tool: entry.tool, operation_id: entry.operation_id, outcome: entry.outcome,
  };
  // No arguments, commands, contents, stdout or raw errors.
  const file = path.join(dir, 'audit.jsonl');
  await localLock(path.join(dir, 'audit.lock'), async () => {
    try {
      if ((await fs.stat(file)).size > 5_000_000) await fs.rename(file, file + '.previous');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.appendFile(file, JSON.stringify(safe) + '\n', { mode: 0o600 });
  });
}
