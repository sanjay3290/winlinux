// A CommonJS consumer of the ESM-only `winlinux` package. This is
// the README example: `await import('winlinux')` works from CommonJS on every
// supported Node.js. `require('winlinux')` works only where Node can require
// ES modules (22.12 and later); the result says which case ran.
'use strict';

async function main() {
  const { connect, WinLinuxUsageError } = await import('winlinux');
  const client = await connect('server.example.test', { username: 'alice', password: 'x' }); // opens nothing
  await client.close();
  let required;
  try {
    required = typeof require('winlinux').connect;
  } catch (err) {
    required = err.code;
  }
  process.stdout.write(
    JSON.stringify({
      connect: typeof connect,
      usageError: typeof WinLinuxUsageError,
      required,
      node: process.versions.node,
    }),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
