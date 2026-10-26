// Every test-created directory is private, including on Windows with broad TEMP ACLs.
import fs from 'node:fs/promises';
import { privateDirectory } from '../src/local-state.js';
if (process.platform === 'win32') {
  const create = fs.mkdtemp.bind(fs);
  fs.mkdtemp = async (...args) => { const dir = await create(...args); await privateDirectory(dir); return dir; };
}
