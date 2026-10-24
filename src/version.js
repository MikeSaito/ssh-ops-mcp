import fs from 'node:fs';
const metadata = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const packageInfo = Object.freeze({ name: metadata.name, version: metadata.version });
