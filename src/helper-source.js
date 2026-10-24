import fs from 'node:fs/promises';

// Assembly happens locally. The server receives one self-contained stdlib script.
export async function loadRemoteSource() {
  const main = await fs.readFile(new URL('./remote_helper.py', import.meta.url), 'utf8');
  const names = JSON.parse(await fs.readFile(new URL('./remote_helpers/manifest.json', import.meta.url), 'utf8'));
  if (!Array.isArray(names) || new Set(names).size !== names.length || names.some(x => typeof x !== 'string' || !/^[a-z_]+$/.test(x))) throw new Error('Invalid helper module manifest.');
  if (main.split('# BUNDLED_HELPERS').length !== 2) throw new Error('Invalid helper assembly marker.');
  const modules = await Promise.all(names.map(name => fs.readFile(new URL('./remote_helpers/' + name + '.py', import.meta.url), 'utf8')));
  return main.replace('# BUNDLED_HELPERS', modules.join('\n\n'));
}
