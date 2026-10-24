import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';

export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export function alive(pid) {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}
export async function atomicJson(file, value) {
  const temp = file + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
  let handle;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(value)); await handle.sync();
    await handle.close(); handle = null;
    for (let attempt = 0; ; attempt++) {
      try { await fs.rename(temp, file); break; }
      catch (error) {
        // Windows readers/scanners may briefly deny replacement. Never unlink the destination.
        if (process.platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(error.code) || attempt >= 8) throw error;
        await delay(Math.min(10 * 2 ** attempt, 100));
      }
    }
  }
  finally { if (handle) await handle.close().catch(() => {}); await fs.unlink(temp).catch(() => {}); }
}
export async function readJson(file) { return JSON.parse(await fs.readFile(file, 'utf8')); }
export async function fileIdentity(file) {
  const info = await fs.stat(file, { bigint: true });
  // DACL changes can change ctime without altering bytes, especially on Windows.
  return [info.dev, info.ino, info.size, info.mtimeNs].map(String).join(':');
}
// Persistent mutex files must never be unlinked, even when not locked.
export async function tryLocalLock(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const legacy = await fs.lstat(file).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (legacy) {
    if (!legacy.isDirectory() || legacy.isSymbolicLink()) throw new Error('Unsafe legacy lock path.');
    const owner = await readJson(path.join(file, 'owner.json')).catch(() => null);
    if (owner && alive(owner.pid)) throw new Error('Stop legacy MCP processes and workers before migrating local locks.');
  }
  const parent = await fs.realpath(path.dirname(file));
  const target = path.join(parent, path.basename(file) + '.mutex.sqlite');
  const handle = await fs.open(target, 'ax', 0o600).catch(error => { if (error.code === 'EEXIST') return null; throw error; });
  if (handle) await handle.close();
  const info = await fs.lstat(target);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('Unsafe mutex file.');
  if (process.platform !== 'win32') await fs.chmod(target, 0o600);
  let db;
  try {
    db = new DatabaseSync(target);
    db.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE');
  } catch (error) {
    if (db) db.close();
    if ([5, 6].includes(error.errcode & 255)) return null;
    throw new Error('Local mutex unavailable; do not repeat modifying work.', { cause: error });
  }
  let released = false;
  return () => { if (!released) { released = true; try { db.exec('ROLLBACK'); } finally { db.close(); } } };
}
export async function localLock(file, action, waitMs = 10000) {
  const started = Date.now();
  while (true) {
    const release = await tryLocalLock(file);
    if (release) { try { return await action(); } finally { release(); } }
    if (Date.now() - started >= waitMs) throw new Error('Local resource is busy; retry status, not the modifying action.');
    await delay(50);
  }
}

function powershell(script, input) {
  return new Promise((resolve, reject) => {
    let phase = 'startup';
    const mark = name => `[Console]::Error.WriteLine('SSH_MCP_PS:${name}'); `;
    const command = mark('entered') + script.replace(psInput, psInput + mark('input')).replace('Add-Type -AssemblyName System.Security;', 'Add-Type -AssemblyName System.Security; ' + mark('assembly')) + '; ' + mark('complete');
    const windowsRoot = process.env.SystemRoot || 'C:\\Windows';
    const executable = path.join(windowsRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const child = spawn(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      // Do not inherit PowerShell 7 module paths into Windows PowerShell 5.1.
      env: { ...process.env, PSModulePath: path.join(windowsRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') },
    });
    const chunks = [];
    const timer = setTimeout(() => { child.kill(); reject(new Error('Local protection operation timed out at ' + phase + '.')); }, 15000);
    child.stdout.on('data', chunk => chunks.push(chunk));
    child.stderr.on('data', bytes => {
      for (const marker of bytes.toString('utf8').matchAll(/SSH_MCP_PS:(entered|input|assembly|complete)/g)) phase = marker[1];
    });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); code === 0 ? resolve(Buffer.concat(chunks).toString('utf8').trim()) : reject(new Error('Windows private storage protection failed at ' + phase + '.')); });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(input));
  });
}
const psInput = "$ErrorActionPreference='Stop'; $taskPayload = [Console]::In.ReadToEnd() | ConvertFrom-Json; ";
export async function privateDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Private directory cannot be a symlink or junction.');
  if (process.platform !== 'win32') { await fs.chmod(directory, 0o700); return; }
  await powershell(psInput + `
    $taskSid = [Security.Principal.WindowsIdentity]::GetCurrent().User;
    $taskSystem = [Security.Principal.SecurityIdentifier]::new('S-1-5-18');
    $taskAcl = Get-Acl -LiteralPath $taskPayload.path;
    $taskAcl.SetAccessRuleProtection($true,$false);
    foreach($taskExisting in @($taskAcl.Access)) { $taskAcl.RemoveAccessRuleSpecific($taskExisting) }
    foreach($taskPrincipal in @($taskSid,$taskSystem)) {
      $taskRule=[Security.AccessControl.FileSystemAccessRule]::new($taskPrincipal,'FullControl','ContainerInherit,ObjectInherit','None','Allow');
      $taskAcl.AddAccessRule($taskRule);
    }
    [IO.DirectoryInfo]::new($taskPayload.path).SetAccessControl($taskAcl);
    $taskCheck=Get-Acl -LiteralPath $taskPayload.path;
    if(!$taskCheck.AreAccessRulesProtected) { throw 'ACL inheritance still enabled' }
    foreach($taskRule in $taskCheck.Access) {
      $taskRuleSid=$taskRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
      if($taskRule.AccessControlType -eq 'Allow' -and $taskRuleSid -notin @($taskSid.Value,'S-1-5-18')) { throw 'Unexpected reader' }
    }
    [Console]::Out.Write('verified');`, { path: directory });
}
export async function sealKey(key) {
  if (process.platform !== 'win32') return { scheme: 'private-file', value: key.toString('base64') };
  const value = await powershell(psInput + `Add-Type -AssemblyName System.Security;
    $taskBytes=[Convert]::FromBase64String($taskPayload.value);
    $taskProtected=[Security.Cryptography.ProtectedData]::Protect($taskBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
    [Console]::Out.Write([Convert]::ToBase64String($taskProtected));`, { value: key.toString('base64') });
  return { scheme: 'windows-dpapi-current-user', value };
}
export async function openKey(sealed) {
  if (sealed.scheme === 'private-file' && process.platform !== 'win32') return Buffer.from(sealed.value, 'base64');
  if (sealed.scheme !== 'windows-dpapi-current-user' || process.platform !== 'win32') throw new Error('Encryption key belongs to a different platform/user.');
  const value = await powershell(psInput + `Add-Type -AssemblyName System.Security;
    $taskBytes=[Convert]::FromBase64String($taskPayload.value);
    $taskPlain=[Security.Cryptography.ProtectedData]::Unprotect($taskBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
    [Console]::Out.Write([Convert]::ToBase64String($taskPlain));`, { value: sealed.value });
  return Buffer.from(value, 'base64');
}
