import crypto from 'node:crypto';
import { once } from 'node:events';
import ssh2 from 'ssh2';
const { Server, utils } = ssh2;

export function makeKey(passphrase) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const plain = privateKey.export({ type: 'pkcs1', format: 'pem' });
  const encoded = passphrase ? privateKey.export({ type: 'pkcs1', format: 'pem', cipher: 'aes-256-cbc', passphrase }) : plain;
  return { plain, encoded, parsed: utils.parseKey(plain) };
}
export async function testServer(key = makeKey()) {
  const host = makeKey(), attempts = [], clients = new Set();
  const server = new Server({ hostKeys: [host.plain] }, client => {
    clients.add(client);
    client.on('close', () => clients.delete(client));
    client.on('error', () => {});
    client.on('authentication', ctx => {
      attempts.push(ctx.method);
      if (ctx.username !== 'test-user') return ctx.reject();
      if (ctx.method === 'password' && ctx.password === 'synthetic-password') return ctx.accept();
      if (ctx.method === 'publickey' && ctx.key.data.equals(key.parsed.getPublicSSH()) && (!ctx.signature || key.parsed.verify(ctx.blob, ctx.signature, ctx.hashAlgo) === true)) return ctx.accept();
      ctx.reject();
    });
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('exec', accept => {
        const stream = accept();
        stream.write('synthetic-output\n'); stream.exit(0); stream.end();
      });
    }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return {
    key, attempts,
    env: { SSH_HOST: '127.0.0.1', SSH_PORT: String(server.address().port), SSH_USERNAME: 'test-user', SSH_AUTH_METHOD: 'password', SSH_PASSWORD: 'synthetic-password', SSH_HOST_FINGERPRINT_SHA256: 'SHA256:' + crypto.createHash('sha256').update(host.parsed.getPublicSSH()).digest('base64').replace(/=+$/, '') },
    async close() { for (const client of clients) client.end(); await new Promise(resolve => server.close(resolve)); },
  };
}
export async function disconnect(client) { const closed = once(client, 'close'); client.end(); await closed; }
