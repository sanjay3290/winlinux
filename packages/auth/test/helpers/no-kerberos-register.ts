// `node --import <this file> <script>`: registers no-kerberos-hooks for the
// whole process, including dynamic import() inside @winlinux/auth.
import { register } from 'node:module';

register('./no-kerberos-hooks.js', import.meta.url);
