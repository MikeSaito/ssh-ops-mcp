import fs from 'node:fs/promises';
import path from 'node:path';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';

// Conservative allow-list validation, not a general effective-access evaluator.
export function validateAcl(report, confidential = true) {
  if (!report || typeof report.current_sid !== 'string' || !Array.isArray(report.entries) || !report.entries.length) throw new Error('Windows ACL inspection unavailable.');
  const trusted = new Set([report.current_sid, 'S-1-5-18', 'S-1-5-32-544']);
  for (const entry of report.entries) {
    if (!trusted.has(entry.owner) || entry.null_dacl || !Array.isArray(entry.rules)) throw new Error('Unsafe Windows ACL owner or DACL.');
    for (const rule of entry.rules) {
      if (!Number.isSafeInteger(rule.mask) || typeof rule.sid !== 'string' || typeof rule.inherit_only !== 'boolean') throw new Error('Unsupported Windows ACL rule.');
      if (!['Allow', 'Deny'].includes(rule.type)) throw new Error('Unsupported Windows ACL rule.');
      if (rule.inherit_only) continue;
      const dangerous = entry.parent ? 0x500d0046 : (confidential ? 0xf00d0117 : 0x500d0116);
      if (rule.type === 'Allow' && !trusted.has(rule.sid) && ((rule.mask >>> 0) & dangerous)) throw new Error('Windows ACL grants untrusted access. Protect the file and its parent directory.');
    }
  }
}
export async function inspectWindowsAcl(file) {
  const root = process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows';
  const executable = path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = "$ErrorActionPreference='Stop'; $p=[Console]::In.ReadToEnd()|ConvertFrom-Json; " +
    "$entries=@(); foreach($item in @(@{path=$p.path;parent=$false},@{path=[IO.Path]::GetDirectoryName($p.path);parent=$true})) {" +
    "$acl=Get-Acl -LiteralPath $item.path; $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl); $rules=@();" +
    "if($null -ne $raw.DiscretionaryAcl){foreach($ace in $raw.DiscretionaryAcl){" +
    "$type=if($ace.AceType -eq 'AccessAllowed'){'Allow'}elseif($ace.AceType -eq 'AccessDenied'){'Deny'}else{'Unsupported'};" +
    "$rules+=@{sid=$ace.SecurityIdentifier.Value;mask=[long]$ace.AccessMask;type=$type;inherit_only=([int]$ace.AceFlags -band 8) -ne 0};}}" +
    "$entries+=@{owner=$raw.Owner.Value;null_dacl=$null -eq $raw.DiscretionaryAcl;parent=$item.parent;rules=$rules};}" +
    "[Console]::Out.Write((@{current_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;entries=$entries}|ConvertTo-Json -Depth 8 -Compress));";
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
      env: { ...process.env, PSModulePath: path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') },
    });
    let output = '', settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
    const timer = setTimeout(() => { child.kill(); finish(new Error('Windows ACL inspection timed out.')); }, 15000);
    child.on('error', () => finish(new Error('Windows ACL inspection unavailable.')));
    child.stdout.on('data', bytes => { output += bytes.toString('utf8'); if (output.length > 262144) { child.kill(); finish(new Error('Windows ACL inspection output exceeded limit.')); } });
    child.on('close', code => { try { if (code !== 0) throw new Error(); finish(null, JSON.parse(output)); } catch { finish(new Error('Windows ACL inspection failed.')); } });
    child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify({ path: file }));
  });
}
export async function readSecureFile(file, { confidential = true, limit = 1024 * 1024 } = {}) {
  file = path.resolve(file);
  const before = await fs.lstat(file).catch(() => { throw new Error('Cannot read selected private file.'); });
  if (!before.isFile() || before.isSymbolicLink() || before.size > limit) throw new Error('Private file must be a bounded regular file, not a symlink.');
  if (process.platform === 'win32') validateAcl(await inspectWindowsAcl(file), confidential);
  else if (before.mode & (confidential ? 0o077 : 0o022)) throw new Error('Private file permissions must be 0600 or stricter; configuration must not be writable by other users.');
  const handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > limit || opened.ino !== before.ino || opened.dev !== before.dev) throw new Error('Private file changed during validation.');
    const bytes = await handle.readFile(), after = await handle.stat(), named = await fs.lstat(file);
    if (bytes.length > limit || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || named.ino !== opened.ino || named.dev !== opened.dev || named.isSymbolicLink()) throw new Error('Private file changed while reading.');
    return bytes;
  } finally { await handle.close(); }
}

export async function checkStateDirectory(directory) {
  const info = await fs.lstat(directory).catch(error => { if (error.code !== 'ENOENT') throw error; return null; });
  if (!info) return false;
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('State directory must not be a symlink or junction.');
  if (process.platform === 'win32') validateAcl(await inspectWindowsAcl(path.resolve(directory)), true);
  else if (info.mode & 0o077) throw new Error('Existing state directory must have mode 0700 or stricter.');
  return true;
}

export async function prepareStateDirectory(directory) {
  if (await checkStateDirectory(directory)) return;
  const { privateDirectory } = await import('./local-state.js');
  await privateDirectory(directory);
  await checkStateDirectory(directory);
}
