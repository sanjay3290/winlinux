#!/usr/bin/env node
// Binary entry point for `winlinux`.
import { runCli } from './app.js';

// Exit only after stdout and stderr flush: pipes are asynchronous on macOS.
function exit(code: number): void {
  process.stdout.write('', () => process.stderr.write('', () => process.exit(code)));
}

const code = await runCli(process.argv.slice(2), {
  env: process.env,
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  exit,
});
exit(code);
