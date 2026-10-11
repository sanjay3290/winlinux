// Writes the npm README of the `winlinux` package: the repository README
// with every relative link made absolute, so the links work on
// npmjs.com. Runs as the package's `prepack` script, so `npm pack` and
// `npm publish` always ship the current README. The output file is not
// committed (.gitignore).
//
//   node scripts/npm-readme.mjs <output file>
import { readFileSync, writeFileSync } from 'node:fs';

const out = process.argv[2];
if (!out) {
  console.error('usage: node scripts/npm-readme.mjs <output file>');
  process.exit(2);
}
const base = 'https://github.com/sanjay3290/winlinux/blob/main/';
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
// Markdown links and images: ](target). Absolute URLs and #anchors stay.
const fixed = readme.replace(/\]\((?!https?:|mailto:|#)([^)\s]+)\)/g, (_m, target) => `](${base}${target.replace(/^\.\//, '')})`);
writeFileSync(out, fixed);
