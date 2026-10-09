import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '..');
const ignored = new Set(['.git', 'node_modules', '.npm-cache', 'dist']);
const failures = [];
let count = 0;
function privatePath(name) {
  return /(?:^|\/)(?:\.env(?:\..*)?|[^/]+\.env)$/.test(name) && !name.endsWith('.example') ||
    /(?:^|\/)(?:\.codex|transfers|downloads|state|\.mcp-state|\.ssh-ops-mcp)(?:\/|$)/.test(name) ||
    /\.(?:pem|key|ppk|mcpenc|part|bak|sqlite|db|log|tgz|zip)$/i.test(name);
}
async function walk(dir, relative = '') {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const name = relative + entry.name;
    if (!relative && ignored.has(entry.name)) continue;
    if (privatePath(name) || entry.isSymbolicLink()) { failures.push(name + ': private/runtime path or symlink'); continue; }
    if (entry.isDirectory()) { await walk(path.join(dir, entry.name), name + '/'); continue; }
    if (!entry.isFile()) { failures.push(name + ': not a regular file'); continue; }
    count++;
    const text = await fs.readFile(path.join(dir, entry.name), 'utf8');
    const normalized = text.replaceAll('\\n', '\n');
    if (/-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]{32,}\r?\n)+/.test(normalized)) failures.push(name + ': private key material');
    if (/(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})/.test(text)) failures.push(name + ': possible credential');
    if (/[A-Z]:[\\/]Users[\\/][^\s"'<>\\/]+/.test(text)) failures.push(name + ': personal absolute path');
  }
}
await walk(root);
// Also catch ignored files accidentally staged with git add -f.
const staged = spawnSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8' });
if (staged.status === 0) for (const name of staged.stdout.split('\0').filter(Boolean)) if (privatePath(name) || /^(?:node_modules|dist)\//.test(name)) failures.push(name + ': unsafe Git-tracked file');
if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
console.log(`Release hygiene OK: ${count} source/documentation files scanned. This is not a full secret scanner or security audit.`);
