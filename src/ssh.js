import ssh2 from 'ssh2';
import { redact } from './security.js';
import { connectionError, sshError } from './ssh-errors.js';
import { buildConnectOptions } from './config.js';
const { Client } = ssh2;

export function quote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }

export async function connect(env = process.env) {
  const options = await buildConnectOptions(env);
  return new Promise((resolve, reject) => {
    const client = new Client();
    let ready = false, settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      client.destroy();
      reject(connectionError(error));
    };
    client.on('error', error => { if (!ready) fail(error); });
    client.once('ready', () => { if (!settled) { ready = true; settled = true; resolve(client); } });
    client.once('close', () => { if (!ready) fail({ code: 'SSH_CLOSED_BEFORE_READY' }); });
    try { client.connect(options); } catch (error) { fail(error); }
  });
}

export async function exec(command, timeoutMs = 60_000, input = '', raw = false, env = process.env) {
  const client = await connect(env);
  try {
    return await new Promise((resolve, reject) => {
      const limit = raw ? 8_000_000 : 5_000_000;
      const out = [], err = [];
      let outBytes = 0, errBytes = 0, finished = false, exitCode;
      const finish = (error, value) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        error ? reject(error) : resolve(value);
      };
      const timer = setTimeout(() => finish(sshError('ssh_command_timeout', 'exec', 'unknown', 'SSH request timed out. Remote execution may still be running; do not repeat a modifying command. Use ssh_operation_start for recoverable work.')), timeoutMs);
      const failed = () => finish(sshError('ssh_exec_failed', 'exec', 'unknown', 'SSH exec failed after dispatch began. Command outcome is unknown; check operation status or remote effects before retrying.'));
      client.once('close', () => finish(sshError('ssh_connection_lost', 'exec', 'unknown', 'SSH connection lost. Command outcome is unknown; do not repeat it blindly.')));
      client.once('error', failed);
      try { client.exec(command, (error, stream) => {
        if (error) return failed();
        stream.on('error', failed);
        stream.on('exit', (code) => { exitCode = code; });
        stream.on('data', (data) => { if (outBytes < limit) out.push(data.subarray(0, limit - outBytes)); outBytes += data.length; });
        stream.stderr.on('data', (data) => { if (errBytes < limit) err.push(data.subarray(0, limit - errBytes)); errBytes += data.length; });
        stream.on('close', (code, signal) => {
          const actualCode = exitCode ?? code;
          if (actualCode === undefined && !signal) return finish(sshError('ssh_exit_status_missing', 'exec', 'unknown', 'SSH channel closed without exit status; command outcome is unknown. Check remote effects before retrying.'));
          const text = (chunks, count) => {
            const value = Buffer.concat(chunks).toString('utf8') + (count > limit ? '\n[output truncated]' : '');
            return raw ? value : redact(value);
          };
          finish(null, { stdout: text(out, outBytes), stderr: text(err, errBytes), exitCode: actualCode, signal });
        });
        stream.end(input);
      }); } catch { failed(); }
    });
  } finally { client.end(); }
}

export async function withSftp(callback, timeoutMs = 300_000, env = process.env) {
  const client = await connect(env);
  let timer;
  try {
    const operation = new Promise((resolve, reject) => {
      client.once('close', () => reject(sshError('ssh_sftp_connection_lost', 'sftp', 'unknown', 'SFTP connection lost. Check transfer status or the destination before retrying a write.')));
      client.once('error', () => reject(sshError('ssh_sftp_failed', 'sftp', 'unknown', 'SFTP failed. Check transfer status or the destination before retrying a write.')));
      client.sftp((error, sftp) => {
        if (error) return reject(sshError('ssh_sftp_open_failed', 'sftp', 'unknown', 'SFTP subsystem could not be opened. Check SFTP availability; do not assume an earlier transfer stopped.'));
        Promise.resolve().then(() => callback(sftp)).then(resolve, reject);
      });
    });
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(sshError('ssh_sftp_timeout', 'sftp', 'unknown', 'SFTP request timed out. Check transfer status or destination integrity before retrying a write.')), timeoutMs);
    })]);
  } finally { clearTimeout(timer); client.end(); }
}
