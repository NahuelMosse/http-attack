// Repository hygiene: tracked text files are clean, CI parses, test temp dirs are removed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './helpers/cli.mjs';

const tracked = () => execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(Boolean);
const TEXT = /\.(mjs|js|json|md|yml|yaml|txt|ps1|sh)$|^(LICENSE|NOTICES\.md)$/;
// C0 controls except tab, line feed and carriage return in CRLF pairs.
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f]|\r(?!\n)/;

test('no tracked text file contains a control character', () => {
  const dirty = tracked().filter((f) => TEXT.test(f) && existsSync(join(ROOT, f)) && CONTROL.test(readFileSync(join(ROOT, f), 'utf8')));
  assert.deepEqual(dirty, []);
});

test('ci.yml declares its jobs and validates the plugin with a pinned claude-code', () => {
  const yml = readFileSync(join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
  const jobs = yml.split(/^jobs:\n/m)[1];
  assert.ok(jobs, 'jobs: present');
  const names = [...jobs.matchAll(/^ {2}([a-z-]+):$/gm)].map((m) => m[1]);
  assert.deepEqual(names, ['test', 'package', 'validate']);
  assert.match(yml, /@anthropic-ai\/claude-code@\d+\.\d+\.\d+ plugin validate/);
});

test('a temp dir made by the test helpers is removed when the process exits', () => {
  const script = "import { tempDir, writeTemp } from './tests/helpers/cli.mjs'; const d = tempDir(); writeTemp(d, 'x.txt', 'x'); console.log(d);";
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: ROOT, encoding: 'utf8' });
  const dir = r.stdout.trim();
  assert.ok(dir.includes('http-attack-test-'), r.stderr);
  assert.equal(existsSync(dir), false);
});
