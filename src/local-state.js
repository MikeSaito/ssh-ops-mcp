import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export function alive(pid) {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}
export async function atomicJson(file, value) {
  const temp = file + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
  const handle = await fs.open(temp, 'wx', 0o600);
  try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); }
  finally { await handle.close(); }
  try { await fs.rename(temp, file); }
  finally { await fs.unlink(temp).catch(() => {}); }
}
export async function readJson(file) { return JSON.parse(await fs.readFile(file, 'utf8')); }
export async function fileIdentity(file) {
  const info = await fs.stat(file, { bigint: true });
  // DACL changes can change ctime without altering bytes, especially on Windows.
  return [info.dev, info.ino, info.size, info.mtimeNs].map(String).join(':');
}
export async function localLock(file, action, waitMs = 10000) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const started = Date.now();
  while (true) {
    try {
      await fs.mkdir(file, { mode: 0o700 });
      await atomicJson(path.join(file, 'owner.json'), { pid: process.pid });
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const owner = await readJson(path.join(file, 'owner.json')).catch(() => null);
      if (owner && !alive(owner.pid)) {
        // This exact private lock only; never recursively delete an arbitrary path.
        await fs.unlink(path.join(file, 'owner.json')).catch(() => {});
        await fs.rmdir(file).catch(() => {});
        continue;
      }
      if (Date.now() - started >= waitMs) throw new Error('Local resource is busy; retry status, not the modifying action.');
      await delay(50);
    }
  }
  try { return await action(); }
  finally {
    await fs.unlink(path.join(file, 'owner.json')).catch(() => {});
    await fs.rmdir(file).catch(() => {});
  }
}

function powershell(script, input) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      // Do not inherit PowerShell 7 module paths into Windows PowerShell 5.1.
      env: { ...process.env, PSModulePath: path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') },
    });
    const chunks = [];
    const timer = setTimeout(() => { child.kill(); reject(new Error('Local protection operation timed out.')); }, 15000);
    child.stdout.on('data', chunk => chunks.push(chunk));
    child.stderr.resume();
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); code === 0 ? resolve(Buffer.concat(chunks).toString('utf8').trim()) : reject(new Error('Windows private storage protection failed.')); });
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
