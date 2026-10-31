// The npm package: what is published, how it is described, and that it agrees with the plugin manifest.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './helpers/cli.mjs';
import { EXPECTED, packedFiles } from './pack-files.mjs';

const json = (...p) => JSON.parse(readFileSync(join(ROOT, ...p), 'utf8'));

test('npm publishes exactly the expected files', () => {
  assert.deepEqual(packedFiles(), [...EXPECTED].sort());
});

test('package.json is publishable and its version matches the plugin manifest', () => {
  const pkg = json('package.json');
  assert.equal(pkg.name, 'http-attack');
  assert.equal(pkg.private, undefined);
  assert.equal(pkg.version, json('.claude-plugin', 'plugin.json').version);
  assert.deepEqual(pkg.bin, { 'http-attack': 'bin/http-attack.mjs' });
  assert.deepEqual(pkg.publishConfig, { access: 'public', provenance: true });
  assert.equal(pkg.dependencies, undefined, 'zero runtime dependencies');
  assert.match(pkg.repository.url, /^git\+https:\/\/github\.com\/NahuelMosse\/http-attack\.git$/);
});
