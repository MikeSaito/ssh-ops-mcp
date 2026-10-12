import crypto from 'node:crypto';
import { once } from 'node:events';
import ssh2 from 'ssh2';

export async function syntheticServer(label, password, bytes = Buffer.from(label), readDelay = 0) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = privateKey.export({ type: 'pkcs1', format: 'pem' });
  const parsed = ssh2.utils.parseKey(key);
  const clients = new Set(), actions = [], attempts = [], files = new Map([['/dump.bin', bytes]]), operations = new Map();
  const pendingReads = []; let holdReads = false;
  const mtime = 1700000000;
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const response = payload => {
    const { action, args } = payload;
    actions.push({ action, args, diagnostic_user: payload.diagnostic_user });
    if (action === 'start') {
      if (operations.has(args.operation_id)) return operations.get(args.operation_id);
      const blocker = [...operations.values()].find(op => op.state === 'running' && op.resource === args.resource);
      if (blocker) return { error: 'Resource busy', code: 'resource_busy', details: { outcome: 'not_started', blocker } };
      const op = { operation_id: args.operation_id, request_id: args.request_id, resource: args.resource, title: args.title, state: 'running', label };
      operations.set(args.operation_id, op); return op;
    }
    if (['status', 'report', 'logs'].includes(action)) return operations.get(args.operation_id) || { error: 'Operation not found' };
    if (action === 'list') return { operations: [...operations.values()] };
    if (action === 'cancel') { const op = operations.get(args.operation_id); if (!op) return { error: 'Operation not found' }; op.state = 'cancelled'; return op; }
    if (action === 'resource_status') return { resource: args.resource, holder: [...operations.values()].find(op => op.resource === args.resource && op.state === 'running') || null };
    if (action === 'file_snapshot') {
      const value = files.get(args.path); if (!value) return { error: 'File not found' };
      return { size: value.length, sha256: hash(value), mtime_ns: String(mtime * 1e9), ctime_ns: String(mtime * 1e9), inode: label, device: 'synthetic' };
    }
    if (action === 'file_hash') { const value = files.get(args.path); return { sha256: value ? hash(value) : null }; }
    if (action === 'write') {
      const prior = files.get(args.path);
      if ((prior ? hash(prior) : null) !== args.expected_sha256) return { error: 'Hash mismatch' };
      if (!args.preview) files.set(args.path, Buffer.from(args.content));
      return { preview: Boolean(args.preview), sha256: hash(Buffer.from(args.content)), label };
    }
    if (action === 'read') return { content: files.get(args.path)?.toString() || '', label };
    return { label, action };
  };
  const server = new ssh2.Server({ hostKeys: [key] }, client => {
    clients.add(client);
    client.on('close', () => clients.delete(client)); client.on('error', error => actions.push({ action: 'ssh-error: ' + error.message }));
    client.on('authentication', ctx => {
      attempts.push(ctx.method);
      if (ctx.username === 'test-user' && ctx.method === 'password' && ctx.password === password) ctx.accept(); else ctx.reject();
    });
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('exec', (accept, reject, info) => {
        const stream = accept(); let input = '';
        stream.on('data', chunk => { input += chunk.toString(); });
        stream.on('end', () => {
          try {
            if (info.command.startsWith('python3 -c ')) stream.write(JSON.stringify(response(JSON.parse(input))));
            else stream.write(label + '\n' + password + '\n');
            stream.exit(0); stream.end();
          } catch { stream.stderr.write('Synthetic helper error'); stream.exit(1); stream.end(); }
        });
      });
      session.on('sftp', accept => {
        const sftp = accept(), handles = new Map(); let next = 0;
        sftp.on('error', error => actions.push({ action: 'sftp-error: ' + error.message }));
        const status = ssh2.utils.sftp.STATUS_CODE;
        sftp.on('OPEN', (id, filename) => {
          if (!files.has(filename)) return sftp.status(id, status.NO_SUCH_FILE);
          const handle = Buffer.from(String(++next)); handles.set(handle.toString(), filename); sftp.handle(id, handle);
        });
        sftp.on('FSTAT', (id, handle) => {
          const data = files.get(handles.get(handle.toString()));
          if (!data) return sftp.status(id, status.FAILURE);
          sftp.attrs(id, { size: data.length, uid: 1000, gid: 1000, mode: 0o100600, atime: mtime, mtime });
        });
        sftp.on('READ', (id, handle, offset, length) => {
          const data = files.get(handles.get(handle.toString()));
          const reply = () => {
            if (sftp.destroyed) return;
            if (!data) sftp.status(id, status.FAILURE);
            else if (offset >= data.length) sftp.status(id, status.EOF);
            else sftp.data(id, data.subarray(offset, offset + length));
          };
          if (holdReads && offset >= 1024 * 1024) pendingReads.push(reply);
          else if (readDelay) setTimeout(reply, readDelay); else reply();
        });
        sftp.on('CLOSE', (id, handle) => { handles.delete(handle.toString()); sftp.status(id, status.OK); });
      });
    }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { actions, attempts, files, operations,
    holdAfterFirstBatch() { holdReads = true; },
    releaseReads() { holdReads = false; for (const reply of pendingReads.splice(0)) reply(); },
    env: { SSH_HOST: '127.0.0.1', SSH_PORT: String(server.address().port), SSH_USERNAME: 'test-user', SSH_AUTH_METHOD: 'password', SSH_PASSWORD: password,
      SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + hashHost(parsed), SSH_DIAGNOSTIC_USER: 'diagnostics-' + label },
    async close() { for (const client of clients) client.destroy(); await new Promise(resolve => server.close(resolve)); },
  };
}
function hashHost(key) { return crypto.createHash('sha256').update(key.getPublicSSH()).digest('base64').replace(/=+$/, ''); }
