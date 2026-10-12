// Module customization hooks (node:module register) that hide the
// `kerberos` package and the @winlinux/krb-session-key addon from one child
// process. The specifier is resolved from a directory that has no
// node_modules, so Node itself raises the ERR_MODULE_NOT_FOUND error that a
// consumer who installed @winlinux/auth with `--omit=optional` gets. Nothing
// else is touched: des.js and hash-wasm resolve as usual.
import type { ResolveHook } from 'node:module';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const HIDDEN = new Set(['kerberos', '@winlinux/krb-session-key']);
const NOWHERE = pathToFileURL(join(tmpdir(), 'winlinux-no-optional-deps', 'consumer.js')).href;

export const resolve: ResolveHook = (specifier, context, next) => {
  if (HIDDEN.has(specifier)) return next(specifier, { ...context, parentURL: NOWHERE });
  return next(specifier, context);
};
