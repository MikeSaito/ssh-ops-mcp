import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { readSecureFile } from '../src/file-security.js';

test('real NTFS ACL rejects a foreign reader, without modifying real settings', { skip: process.platform !== 'win32' }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-acl-')), file = path.join(dir, 'synthetic.txt');
  try {
    await fs.writeFile(file, 'synthetic-acl-value', { mode: 0o600 });
    assert.equal((await readSecureFile(file)).toString(), 'synthetic-acl-value');
    const root = process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows';
    const script = "$ErrorActionPreference='Stop';$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;$acl=Get-Acl -LiteralPath $p.path;" +
      "$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'Read','Allow');" +
      "$acl.AddAccessRule($rule);[IO.FileInfo]::new($p.path).SetAccessControl($acl);";
    const result = spawnSync(path.join(root, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], { input: JSON.stringify({ path: file }), encoding: 'utf8', windowsHide: true,
        env: { ...process.env, PSModulePath: path.join(root, 'System32/WindowsPowerShell/v1.0/Modules') } });
    assert.equal(result.status, 0, result.stderr);
    await assert.rejects(readSecureFile(file), /untrusted access/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
