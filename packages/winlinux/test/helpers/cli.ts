// Spawns the built `winlinux` binary (dist/cli/main.js) with no TTY.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLI = fileURLToPath(new URL('../../dist/cli/main.js', import.meta.url));

// An empty HOME for every spawned CLI, so a developer's own
// ~/.winlinux/config never changes a test. A test that needs
// profiles passes its own HOME.
export const EMPTY_HOME = mkdtempSync(join(tmpdir(), 'winlinux-home-'));

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
  argv: string[];
}

export function runCli(args: string[], env: Record<string, string | undefined> = {}, input = ''): Promise<CliResult> {
  const argv = [CLI, ...args];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argv, {
      env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1', HOME: EMPTY_HOME, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr, argv }));
    child.stdin.end(input);
  });
}
