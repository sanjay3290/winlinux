// Live test runner against a real Windows Server with WinRM enabled.
// Not part of `npm test` (this file is not named *.test.ts).
// Run with: npm run test:live -w @winlinux/winrm
// Setup and env: see ./README.md. Exits 2 when the env is incomplete, 1
// when a scenario fails, 0 when all scenarios pass. It skips nothing: a
// scenario whose env is missing (the Kerberos one on a workgroup VM)
// is reported as env incomplete, the others run, and the exit code is 2
// unless one of them failed.
import { describe } from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthProvider } from '@winlinux/auth';
import { krb5Conf, LIVE_ENV_HELP, liveConfigFromEnv } from './config.js';
import { registerLiveTests, splitScenarios } from './scenarios.js';

const result = liveConfigFromEnv(process.env);
if (!result.ok) {
  console.error(`test:live cannot run:\n  - ${result.problems.join('\n  - ')}\n\n${LIVE_ENV_HELP}`);
  process.exit(2);
}

const cfg = result.config;
console.log(
  `test:live: host=${cfg.host} http=${cfg.httpPort} https=${cfg.httpsPort} tlsVerify=${cfg.tlsVerify} ` +
    `user=${cfg.credentials.domain ? `${cfg.credentials.domain}\\` : ''}${cfg.credentials.username} ` +
    `realm=${cfg.credentials.realm ?? '-'} kdc=${cfg.kdc ?? '-'} ` +
    `general=${cfg.tls ? 'HTTPS' : 'HTTP'}+${cfg.mechanism}`,
);

// WINRM_KDC: kinit and the GSS library read KRB5_CONFIG, so one generated
// file points both at that KDC for the realm.
if (cfg.kdc && cfg.credentials.realm) {
  const file = join(mkdtempSync(join(tmpdir(), 'winlinux-live-krb5-')), 'krb5.conf');
  writeFileSync(file, krb5Conf(cfg.credentials.realm, cfg.kdc, cfg.host));
  process.env['KRB5_CONFIG'] = file;
  console.log(`test:live: KRB5_CONFIG=${file}`);
}

const { runnable, incomplete } = splitScenarios(cfg);
for (const { scenario, problems } of incomplete) {
  console.log(`# env incomplete: ${scenario.name}\n#   - ${problems.join('\n#   - ')}`);
}

describe(`WinRM live against ${cfg.host}`, () => {
  registerLiveTests(
    cfg,
    {
      providerFor: (mechanism) => createAuthProvider(mechanism),
      log: (message) => console.log(`# ${message}`),
    },
    runnable,
  );
});

process.on('exit', () => {
  if (incomplete.length === 0 || (process.exitCode ?? 0) !== 0) return;
  console.error(`test:live: env incomplete for ${incomplete.length} scenario(s), see the '# env incomplete' lines above`);
  process.exitCode = 2;
});
