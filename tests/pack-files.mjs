// node tests/pack-files.mjs [tarball]: fails unless the files npm would publish (or the given tarball holds) are exactly
// the ones in tests/expected-package-files.json. Without an argument it asks `npm pack --dry-run`.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const expected = JSON.parse(readFileSync(join(root, 'tests', 'expected-package-files.json'), 'utf8'));

export function packedFiles(tarball) {
  if (tarball) {
    const out = execFileSync('tar', ['-tzf', basename(tarball)], { cwd: dirname(resolve(tarball)), encoding: 'utf8' }) // relative name: GNU tar reads `D:` as a host;
    return out.split(/\r?\n/).filter((l) => l && !l.endsWith('/')).map((l) => l.replace(/^package\//, '')).sort();
  }
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const out = execFileSync(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', shell: process.platform === 'win32' });
  return JSON.parse(out)[0].files.map((f) => f.path).sort();
}

export const EXPECTED = expected;

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const actual = packedFiles(process.argv[2]);
  const missing = expected.filter((f) => !actual.includes(f));
  const extra = actual.filter((f) => !expected.includes(f));
  if (missing.length || extra.length) {
    console.error(`package file list differs\n  missing: ${missing.join(', ') || '-'}\n  unexpected: ${extra.join(', ') || '-'}`);
    process.exit(1);
  }
  console.log(`package file list ok (${actual.length} files)`);
}
