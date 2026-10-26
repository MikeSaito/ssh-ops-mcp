import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { privateDirectory } from '../src/local-state.js';
import { workerEnvironment } from '../src/config.js';
const run = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
if (!process.env.npm_execpath) throw new Error('Run this check with npm run check:install.');
const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-install-'));
await privateDirectory(dir);
try {
  const packed = await run(process.execPath, [process.env.npm_execpath, 'pack', '--ignore-scripts', '--json', '--pack-destination', dir], { cwd: root, windowsHide: true });
  const [archive] = JSON.parse(packed.stdout);
  assert.ok(archive.files.some(file => file.path === 'src/remote_helpers/search.py'));
  assert.ok(!archive.files.some(file => /(?:^|\/)(?:node_modules|transfers|servers\.json|\.env)$/.test(file.path)));
  await run(process.execPath, [process.env.npm_execpath, 'install', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', dir, path.join(dir, archive.filename)],
    { cwd: dir, windowsHide: true, timeout: 180000, maxBuffer: 1024 * 1024 });
  const metadata = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const entry = path.join(dir, 'node_modules', metadata.name, 'bin/ssh-ops-mcp.js');
  const env = workerEnvironment();
  const result = await run(process.execPath, ['--', entry, '--version'], { cwd: dir, env, windowsHide: true });
  assert.equal(result.stdout.trim(), metadata.version);
  await run(process.execPath, ['--', entry, '--help'], { cwd: dir, env, windowsHide: true });
  console.log('Clean source-package installation and CLI verified. No SSH connection requested.');
} finally { await fs.rm(dir, { recursive: true, force: true }); }
