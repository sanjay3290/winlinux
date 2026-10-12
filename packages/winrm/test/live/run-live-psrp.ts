// PSRP live runner against a real Windows Server. Not part of
// `npm test`. Run with: npm run test:live:psrp -w @winlinux/winrm
// Same env as run-live.ts (see ./README.md); WINLINUX_PSRP_RECORD=<dir>
// records redacted fixtures. Exit 2 when the env is incomplete, 1 when a
// scenario fails, 0 when all pass.
import { describe } from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthProvider } from '@winlinux/auth';
import { krb5Conf, LIVE_ENV_HELP, liveConfigFromEnv } from './config.js';
import { registerPsrpLiveTests, splitPsrpScenarios } from './psrp-scenarios.js';
import { recorderFromEnv } from './psrp-recorder.js';

const result = liveConfigFromEnv(process.env);
if (!result.ok) {
  console.error(`test:live:psrp cannot run:\n  - ${result.problems.join('\n  - ')}\n\n${LIVE_ENV_HELP}`);
  process.exit(2);
}
const cfg = result.config;
console.log(`test:live:psrp: host=${cfg.host} http=${cfg.httpPort} https=${cfg.httpsPort} tlsVerify=${cfg.tlsVerify} general=${cfg.tls ? 'HTTPS' : 'HTTP'}+${cfg.mechanism}`);

if (cfg.kdc && cfg.credentials.realm) {
  const file = join(mkdtempSync(join(tmpdir(), 'winlinux-live-krb5-')), 'krb5.conf');
  writeFileSync(file, krb5Conf(cfg.credentials.realm, cfg.kdc, cfg.host));
  process.env['KRB5_CONFIG'] = file;
}

const recorder = recorderFromEnv(process.env, 'live');
if (recorder) console.log(`test:live:psrp: recording redacted fixtures to ${process.env['WINLINUX_PSRP_RECORD']}`);

const { runnable, incomplete } = splitPsrpScenarios(cfg);
for (const { scenario, problems } of incomplete) {
  console.log(`# env incomplete: ${scenario.name}\n#   - ${problems.join('\n#   - ')}`);
}

describe(`PSRP live against ${cfg.host}`, () => {
  registerPsrpLiveTests(
    cfg,
    {
      providerFor: (mechanism) => createAuthProvider(mechanism),
      log: (message) => console.log(`# ${message}`),
      ...(recorder ? { trace: (e) => recorder.trace(e) } : {}),
    },
    runnable,
  );
});

process.on('exit', () => {
  if (incomplete.length === 0 || (process.exitCode ?? 0) !== 0) return;
  console.error(`test:live:psrp: env incomplete for ${incomplete.length} scenario(s), see the '# env incomplete' lines above`);
  process.exitCode = 2;
});
