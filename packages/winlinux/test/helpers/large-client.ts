// Child process for winrm-copy-large.test.ts: one get or put over WinRM,
// with this process's memory sampled, so the numbers are the client's
// alone (the mock runs in the parent). Prints one JSON line.
// argv: <put|get|hold> <port> <password> <localPath> <remotePath>
// `hold` is the negative control: it reads the whole local file into
// memory and keeps it, as a client that buffered the file would, so the
// test can prove its memory check catches that.
// The parent runs this with --expose-gc: the baseline is taken after a
// full collection, so garbage from the warm-up does not count.
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { createClient } from '../../dist/client.js';
import { realDeps } from '../../dist/real-deps.js';

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

const [mode, port, password, localPath, remotePath] = process.argv.slice(2) as [string, string, string, string, string];
const client = createClient(
  '127.0.0.1',
  {
    username: 'tester',
    password,
    auth: 'basic',
    winrm: { tls: true, tlsVerify: false, port: Number(port) },
    smb: { port: await freePort() },
    transfer: { via: 'winrm' },
  },
  realDeps(),
);

const usage = () => {
  const m = process.memoryUsage();
  return { rss: m.rss, heap: m.heapUsed + m.arrayBuffers };
};
// Warm up: open the WinRM session and load the code paths first.
await client.runPowerShell('$null');
(globalThis as { gc?: () => void }).gc?.();
const base = usage();
let peak = { ...base };
const timer = setInterval(() => {
  const now = usage();
  peak = { rss: Math.max(peak.rss, now.rss), heap: Math.max(peak.heap, now.heap) };
}, 10);
const start = performance.now();
let held: Buffer | undefined;
try {
  if (mode === 'put') await client.put(localPath, 'Data', remotePath);
  else if (mode === 'get') await client.get('Data', remotePath, localPath);
  else held = readFileSync(localPath);
} finally {
  clearInterval(timer);
  await client.close();
}
const now = usage();
peak = { rss: Math.max(peak.rss, now.rss), heap: Math.max(peak.heap, now.heap) };
if (held) held[0] = held[0] ?? 0; // keep it alive until the last sample
process.stdout.write(`${JSON.stringify({ ms: performance.now() - start, rss: peak.rss - base.rss, heap: peak.heap - base.heap })}\n`);
