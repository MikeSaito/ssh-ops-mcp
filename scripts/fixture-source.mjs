import fs from 'node:fs/promises';
import path from 'node:path';

// Test containers receive source/dependencies, never the checkout's private runtime data.
export async function prepareFixtureSource(root, target) {
  await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const filter = source => !/(?:^|[\\/])(?:\.env(?:\.[^\\/]*)?|[^\\/]+\.env|servers\.json|transfers|downloads|state|__pycache__)$/.test(source);
  for (const name of ['src', 'scripts', 'test', 'node_modules', 'bin']) {
    const source = path.join(root, name);
    if (await fs.stat(source).then(info => info.isDirectory(), error => { if (error.code === 'ENOENT') return false; throw error; }))
      await fs.cp(source, path.join(target, name), { recursive: true, filter, verbatimSymlinks: true });
  }
  for (const name of ['package.json', 'package-lock.json']) await fs.copyFile(path.join(root, name), path.join(target, name));
}
