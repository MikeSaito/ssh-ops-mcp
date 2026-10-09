import crypto from 'node:crypto';
export const MAGIC = Buffer.from('SSHMCPENC1\n');
const MAX_CHUNK = 1024 * 1024;
function aad(id, position) { return Buffer.from(id + ':' + position); }
export function encryptFrame(key, id, position, bytes) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad(id, position));
  const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
  const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length);
  return Buffer.concat([size, nonce, cipher.getAuthTag(), encrypted]);
}
export async function scanPartial(handle, key, id, consume = () => {}) {
  const size = (await handle.stat()).size;
  const hash = crypto.createHash('sha256');
  let fileOffset = 0, position = 0;
  if (key) {
    const magic = Buffer.alloc(MAGIC.length);
    await handle.read(magic, 0, magic.length, 0);
    if (!magic.equals(MAGIC)) throw new Error('Encrypted file header is invalid.');
    fileOffset = MAGIC.length;
  }
  while (fileOffset < size) {
    let bytes, frameLength;
    if (key) {
      const header = Buffer.alloc(32);
      if ((await handle.read(header, 0, 32, fileOffset)).bytesRead < 32) break;
      const length = header.readUInt32BE(0);
      if (length < 1 || length > MAX_CHUNK) throw new Error('Encrypted frame size is invalid.');
      if (fileOffset + 32 + length > size) break;
      const encrypted = Buffer.alloc(length);
      await handle.read(encrypted, 0, length, fileOffset + 32);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, header.subarray(4, 16));
      decipher.setAAD(aad(id, position)); decipher.setAuthTag(header.subarray(16, 32));
      bytes = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      frameLength = 32 + length;
    } else {
      bytes = Buffer.alloc(Math.min(MAX_CHUNK, size - fileOffset));
      const read = await handle.read(bytes, 0, bytes.length, fileOffset);
      bytes = bytes.subarray(0, read.bytesRead); frameLength = bytes.length;
      if (!frameLength) break;
    }
    hash.update(bytes); await consume(bytes);
    fileOffset += frameLength; position += bytes.length;
  }
  return { hash, position, fileOffset, complete: fileOffset === size };
}
