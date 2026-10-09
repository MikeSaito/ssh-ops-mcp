import ssh2 from 'ssh2';
import { redact } from './security.js';
import { buildConnectOptions } from './config.js';
const { Client } = ssh2;

export function quote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }

export async function connect(env = process.env) {
  const options = await buildConnectOptions(env);
  return new Promise((resolve, reject) => {
    const client = new Client();
    let ready = false;
    client.on('error', (error) => { if (!ready) { client.destroy(); reject(error); } });
    client.once('ready', () => { ready = true; resolve(client); });
    client.once('close', () => { if (!ready) reject(new Error('SSH closed before authentication.')); });
    try { client.connect(options); } catch (error) { client.destroy(); reject(error); }
  });
}

export async function exec(command, timeoutMs = 60_000, input = '', raw = false) {
  const client = await connect();
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
      const timer = setTimeout(() => finish(new Error('SSH request timed out. Remote execution may still be running; do not repeat a modifying command. Use ssh_operation_start for recoverable work.')), timeoutMs);
      client.once('close', () => finish(new Error('SSH connection lost. Command outcome is unknown; do not repeat it blindly.')));
      client.once('error', (error) => finish(error));
      client.exec(command, (error, stream) => {
        if (error) return finish(error);
        stream.on('error', (e) => finish(e));
        stream.on('exit', (code) => { exitCode = code; });
        stream.on('data', (data) => { if (outBytes < limit) out.push(data.subarray(0, limit - outBytes)); outBytes += data.length; });
        stream.stderr.on('data', (data) => { if (errBytes < limit) err.push(data.subarray(0, limit - errBytes)); errBytes += data.length; });
        stream.on('close', (code, signal) => {
          const actualCode = exitCode ?? code;
          if (actualCode === undefined && !signal) return finish(new Error('SSH channel closed without exit status; command outcome is unknown.'));
          const text = (chunks, count) => {
            const value = Buffer.concat(chunks).toString('utf8') + (count > limit ? '\n[output truncated]' : '');
            return raw ? value : redact(value);
          };
          finish(null, { stdout: text(out, outBytes), stderr: text(err, errBytes), exitCode: actualCode, signal });
        });
        stream.end(input);
      });
    });
  } finally { client.end(); }
}

export async function withSftp(callback, timeoutMs = 300_000) {
  const client = await connect();
  let timer;
  try {
    const operation = new Promise((resolve, reject) => {
      client.once('close', () => reject(new Error('SFTP connection lost.')));
      client.once('error', reject);
      client.sftp((error, sftp) => {
        if (error) return reject(error);
        Promise.resolve().then(() => callback(sftp)).then(resolve, reject);
      });
    });
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('SFTP request timed out.')), timeoutMs);
    })]);
  } finally { clearTimeout(timer); client.end(); }
}
