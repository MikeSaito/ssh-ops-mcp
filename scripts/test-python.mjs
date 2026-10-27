import { spawnSync } from 'node:child_process';
const command = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const result = spawnSync(command, ['-B', '-m', 'unittest', 'discover', '-s', 'test', '-p', '*_test.py', '-v'], { stdio: 'inherit', windowsHide: true });
if (result.error) console.error('Python 3 test runner is unavailable.');
process.exitCode = result.status ?? 1;
