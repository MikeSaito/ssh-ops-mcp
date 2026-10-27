import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { prepareFixtureSource } from '../scripts/fixture-source.mjs';

test('real SSH staging excludes checkout credentials, profiles and runtime downloads', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshops-staging-'));
  const source = path.join(dir, 'checkout'), target = path.join(dir, 'staged');
  try {
    for (const name of ['src', 'scripts', 'test', 'node_modules', 'transfers']) await fs.mkdir(path.join(source, name), { recursive: true });
    for (const name of ['package.json', 'package-lock.json']) await fs.writeFile(path.join(source, name), '{}');
    for (const name of ['.env', 'servers.json', 'transfers/private-dump', 'src/private.env']) await fs.writeFile(path.join(source, name), 'synthetic-private-excluded');
    await fs.writeFile(path.join(source, 'src/index.js'), '// synthetic source');
    await prepareFixtureSource(source, target);
    assert.equal(await fs.readFile(path.join(target, 'src/index.js'), 'utf8'), '// synthetic source');
    for (const name of ['.env', 'servers.json', 'transfers', 'src/private.env']) await assert.rejects(fs.access(path.join(target, name)));
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
