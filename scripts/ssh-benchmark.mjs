import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { connect, quote } from '../src/ssh.js';
import { rpc } from '../src/remote.js';
import { loadRemoteSource } from '../src/helper-source.js';
import { privateDirectory } from '../src/local-state.js';
import { workerEnvironment } from '../src/config.js';

const stats = values => {
  const ordered = [...values].sort((a, b) => a - b);
  return { samples: ordered.length, median_ms: +ordered[Math.floor(ordered.length / 2)].toFixed(2),
    p95_ms: +ordered[Math.ceil(ordered.length * 0.95) - 1].toFixed(2) };
};
async function samples(fn, count = 20) {
  const values = [];
  for (let i = 0; i < count; i++) { const start = performance.now(); await fn(); values.push(performance.now() - start); }
  return stats(values);
}
async function channel(client, command, input) {
  return new Promise((resolve, reject) => {
    let output = '', stream;
    const timer = setTimeout(() => { stream?.destroy(); reject(new Error('Synthetic benchmark channel timed out.')); }, 15000);
    client.exec(command, (error, opened) => {
      if (error) { clearTimeout(timer); reject(error); return; }
      stream = opened;
      stream.on('error', error => { clearTimeout(timer); reject(error); });
      stream.on('data', bytes => { output += bytes.toString('utf8'); if (output.length > 16384) stream.destroy(); });
      stream.on('close', code => {
        clearTimeout(timer);
        try { if (code !== 0 || JSON.parse(output).error) throw new Error(); resolve(); }
        catch { reject(new Error('Synthetic benchmark helper failed.')); }
      });
      stream.end(input);
    });
  });
}
export async function benchmark(env, label) {
  const source = await loadRemoteSource(), target = '/home/synthetic/config.txt', phases = new Map();
  const observer = sample => { if (!phases.has(sample.phase)) phases.set(sample.phase, []); phases.get(sample.phase).push(sample.duration_ms); };
  const setup = await samples(async () => { const c = await connect(env, observer); c.end(); });
  const cold = await samples(() => rpc('file_hash', { path: target }, 15000, env));
  const client = await connect(env);
  let prototype;
  try {
    const command = 'python3 -c ' + quote('import json,sys; p=json.loads(sys.stdin.read()); exec(compile(p["source"],"mcp-helper","exec"))');
    const input = JSON.stringify({ source, action: 'file_hash', args: { path: target } });
    prototype = await samples(() => channel(client, command, input));
  } finally { client.end(); }
  const state = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-benchmark-'));
  await privateDirectory(state);
  const root = path.resolve(import.meta.dirname, '..');
  const connection = path.join(state, 'synthetic.env');
  await fs.writeFile(connection, Object.entries(env).filter(([, value]) => typeof value === 'string').map(([key, value]) => key + '=' + JSON.stringify(value)).join('\n'), { mode: 0o600 });
  const publicCopy = await fs.access(path.join(root, 'bin/ssh-ops-mcp.js')).then(() => true, () => false);
  const transport = new StdioClientTransport({ command: process.execPath,
    args: ['--', path.join(root, publicCopy ? 'bin/ssh-ops-mcp.js' : 'src/index.js'), '--connection-file', connection],
    env: { ...workerEnvironment(), ...env, SSH_MCP_STATE_DIR: path.join(state, 'state') }, stderr: 'pipe' });
  const mcp = new Client({ name: 'synthetic-benchmark', version: '1' });
  let endToEnd;
  try {
    await mcp.connect(transport);
    endToEnd = await samples(async () => {
      const value = await mcp.callTool({ name: 'ssh_file_hash', arguments: { path: target } });
      if (value.isError) throw new Error('Synthetic MCP benchmark failed.');
    });
  } finally { await mcp.close(); await transport.close(); await fs.rm(state, { recursive: true, force: true }); }
  return { label, configuration: 'local synthetic Linux SSH, sequential calls', connection: setup,
    connection_phases: Object.fromEntries([...phases].map(([name, values]) => [name, stats(values)])),
    helper_per_call: cold, helper_retained_transport_prototype: prototype, mcp_per_call: endToEnd,
    production_pool: 'not enabled: prototype measurements do not validate pooled MCP cancellation, contention or memory bounds' };
}
