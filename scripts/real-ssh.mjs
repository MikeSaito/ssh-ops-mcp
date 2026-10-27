import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { privateDirectory } from '../src/local-state.js';
import { prepareFixtureSource } from './fixture-source.mjs';

const root = path.resolve(import.meta.dirname, '..'), run = promisify(execFile);
const suffix = crypto.randomBytes(5).toString('hex'), front = 'sshops-front-' + suffix, back = 'sshops-back-' + suffix;
const image = 'sshops-fixture:' + suffix, alpineImage = 'sshops-alpine:' + suffix, containers = [], networks = [];
const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-daemons-'));
await privateDirectory(dir);
async function docker(...args) {
  return (await run('docker', args, { cwd: root, windowsHide: true, timeout: 240000, maxBuffer: 4 * 1024 * 1024 })).stdout.trim();
}
async function until(fn) {
  const deadline = Date.now() + 30000;
  do { if (await fn()) return; await new Promise(resolve => setTimeout(resolve, 200)); } while (Date.now() < deadline);
  throw new Error('Synthetic daemon readiness timed out.');
}
async function fixture(kind, network, selectedImage = image) {
  const name = 'sshops-' + kind + '-' + suffix;
  await docker('run', '-d', '--rm', '--name', name, '--hostname', kind + '-fixture', '--network', network,
    '--network-alias', kind + '.fixture.invalid', selectedImage, kind === 'private' ? 'dropbear' : kind);
  containers.push(name);
  let fingerprint;
  try {
    await until(async () => {
      try {
        fingerprint = (await docker('exec', name, 'ssh-keygen', '-lf', '/fixture/host.pub', '-E', 'sha256')).split(/\s+/)[1];
        await docker('exec', name, 'node', '-e', "const s=require('net').connect(22,'127.0.0.1');s.on('connect',()=>{s.destroy();process.exit(0)});s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),1000)");
        return Boolean(fingerprint?.startsWith('SHA256:'));
      } catch { return false; }
    });
  } catch (error) { console.error(await docker('logs', '--tail', '30', name).catch(() => 'Fixture exited.')); throw error; }
  return { name, env: { SSH_HOST: kind + '.fixture.invalid', SSH_PORT: '22', SSH_USERNAME: 'synthetic',
    SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-fixture-password', SSH_HOST_FINGERPRINT_SHA256: fingerprint } };
}
try {
  await docker('version', '--format', '{{.Server.Version}}');
  const buildArgs = process.env.SSHOPS_TEST_NODE === '24' ? ['--build-arg', 'NODE_IMAGE=mirror.gcr.io/library/node:24-bookworm@sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a'] : [];
  await docker('build', ...buildArgs, '-f', 'test/real-ssh/Dockerfile', '-t', image, '.');
  await docker('build', '-f', 'test/real-ssh/Dockerfile.alpine', '-t', alpineImage, '.');
  for (const name of [front, back]) { await docker('network', 'create', '--internal', name); networks.push(name); }
  const open = await fixture('openssh', front), drop = await fixture('dropbear', front);
  const alpine = await fixture('alpine', front, alpineImage);
  const noSftp = await fixture('nosftp', front), privateTarget = await fixture('private', back);
  await docker('network', 'connect', back, open.name);
  const keys = path.join(dir, 'keys');
  await fs.mkdir(keys, { mode: 0o700 });
  for (const server of [open, drop, alpine]) for (const locked of [false, true]) {
    const file = path.join(keys, server.name + (locked ? '-locked' : '-plain'));
    await docker('cp', server.name + ':/fixture/client' + (locked ? '-locked' : ''), file); await fs.chmod(file, 0o600);
  }
  const source = path.join(dir, 'source');
  await prepareFixtureSource(root, source);
  const command = 'cp -a /source /tmp/project && cp -a /keys /tmp/keys && chmod 700 /tmp/keys && chmod 600 /tmp/keys/* && cd /tmp/project && node scripts/real-ssh-client.mjs' +
    (process.argv.includes('--bench') ? ' --bench' : '') + ' && npm test && npm run test:operations';
  const runner = 'sshops-client-' + suffix;
  containers.push(runner);
  const args = ['run', '--rm', '--name', runner, '--entrypoint', '/bin/sh', '--network', front,
    '--mount', 'type=bind,src=' + source + ',dst=/source,readonly', '--mount', 'type=bind,src=' + keys + ',dst=/keys,readonly',
    '-e', 'SSHOPS_FIXTURES=' + JSON.stringify({ open, drop, alpine, noSftp, privateTarget }), image, '-c', command];
  await new Promise((resolve, reject) => {
    const child = spawn('docker', args, { cwd: root, windowsHide: true, stdio: 'inherit' });
    const timer = setTimeout(() => { child.kill(); reject(new Error('Synthetic SSH suite exceeded 10 minutes.')); }, 600000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error('Synthetic SSH suite failed: ' + code)); });
  });
} finally {
  for (const name of containers.reverse()) await docker('stop', '-t', '2', name).catch(() => {});
  for (const name of networks.reverse()) await docker('network', 'rm', name).catch(() => {});
  await docker('image', 'rm', image).catch(() => {});
  await docker('image', 'rm', alpineImage).catch(() => {});
  await fs.rm(dir, { recursive: true, force: true });
}
