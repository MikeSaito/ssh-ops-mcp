import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { redact } from '../src/security.js';
import { loadRemoteSource } from '../src/helper-source.js';
import { packageInfo } from '../src/version.js';

test('JavaScript and Python masking share exact fixtures, newlines and idempotence', async () => {
  const fixtures = JSON.parse(await fs.readFile(new URL('./redaction-fixtures.json', import.meta.url), 'utf8'));
  const security = await fs.readFile(new URL('../src/remote_helpers/security.py', import.meta.url), 'utf8');
  const script = 'import json,re,sys; p=json.load(sys.stdin); ns={"re":re}; exec(p["source"],ns); print(json.dumps([[ns["masked"](x["input"]),ns["masked"](x["output"])] for x in p["fixtures"]]))';
  const result = spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-B', '-c', script], { input: JSON.stringify({ source: security, fixtures }), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const python = JSON.parse(result.stdout);
  for (const [index, fixture] of fixtures.entries()) {
    assert.equal(redact(fixture.input), fixture.output, 'JS fixture ' + index);
    assert.deepEqual(python[index], [fixture.output, fixture.output], 'Python fixture ' + index);
  }
});
test('standalone helper assembly and package versions stay consistent', async () => {
  const source = await loadRemoteSource();
  assert.ok(!source.includes('# BUNDLED_HELPERS'));
  for (const name of ['dispatch', 'history_save', 'write', 'state_cleanup']) assert.ok(source.includes('def ' + name + '('));
  const lock = JSON.parse(await fs.readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
  assert.equal(lock.version, packageInfo.version); assert.equal(lock.packages[''].version, packageInfo.version);
});
