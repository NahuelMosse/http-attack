// The documentation matches the code: SKILL.md's severity table is the registry, and every rule the code emits is in it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, SKILL } from './helpers/cli.mjs';
import { RULES } from '../skills/http-attack/scripts/lib/registry.mjs';

const skill = readFileSync(join(SKILL, 'SKILL.md'), 'utf8');
const reference = (name) => readFileSync(join(SKILL, 'references', `${name}.md`), 'utf8');

const sourceFiles = (dir) => readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? sourceFiles(join(dir, f)) : f.endsWith('.mjs') ? [join(dir, f)] : []));

test("references/severity.md lists exactly the registry rules with their severities", () => {
  const rows = [...reference('severity').matchAll(/^\| `([a-z-]+)` \| (critical|high|medium|low|-) \|/gm)].map((m) => [m[1], m[2] === '-' ? null : m[2]]);
  assert.deepEqual(Object.fromEntries(rows), Object.fromEntries(Object.entries(RULES).map(([k, v]) => [k, v.severity])));
  assert.equal(rows.length, Object.keys(RULES).length, 'no rule listed twice');
});

test('every rule the code emits is registered, and every registered rule is emitted', () => {
  const code = sourceFiles(join(SKILL, 'scripts', 'lib')).filter((f) => !f.endsWith('registry.mjs')).map((f) => readFileSync(f, 'utf8')).join('\n');
  const emitted = new Set([...code.matchAll(/\.fail\(\s*'([a-z-]+)'/g)].map((m) => m[1]));
  for (const rule of emitted) assert.ok(rule in RULES, `${rule} is emitted but not registered`);
  const viaOther = new Set(['not-run']); // rows made by notRun()
  for (const rule of Object.keys(RULES)) assert.ok(emitted.has(rule) || viaOther.has(rule) || code.includes(`'${rule}'`), `${rule} is registered but never emitted`);
});

test('SKILL.md follows the plugin conventions', () => {
  const front = skill.match(/^---\n([\s\S]*?)\n---/)[1];
  assert.match(front, /^name: http-attack$/m);
  assert.doesNotMatch(front, /allowed-tools/, 'a tool that deletes rows and locks the database must prompt on every run');
  assert.ok(!skill.includes('${env:CLAUDE_SKILL_DIR}'), '${CLAUDE_SKILL_DIR} is a text substitution, not an environment variable');
  assert.ok(!skill.includes('--fault-cmd'), 'fault commands are config-only');
  assert.ok(!/CORS/.test(skill), 'the script never sends an Origin on ordinary requests, so CORS is not a common header');
  assert.ok(front.match(/^description: (.*)$/m)[1].length <= 650, 'the description stays short');
  assert.ok(skill.split('\n').length < 500);
  assert.ok(skill.includes('${CLAUDE_SKILL_DIR}/scripts/http-attack.mjs'));
  assert.ok(!skill.includes('<skill-dir>'));
  assert.ok(!/allow[-_]remote/i.test(skill), 'the human-only override is not documented to the agent');
  assert.match(skill, /every remaining one is suppressed in the config with its/);
});

test('the docs explain the paired server-error and stack-leak ids and the lingering close', () => {
  assert.match(reference('severity'), /`server-error`.*and `stack-leak`[\s\S]*?on purpose|reported twice on purpose/);
  assert.match(reference('config'), /`not-run:<probe>`/);
  const fixes = reference('fixes');
  assert.match(fixes, /lingering close/);
  assert.doesNotMatch(fixes, /413 at the limit, then close the connection/);
});

test('every option in --help is accepted by the parser and no flag is documented that does not exist', async () => {
  const { HELP, FLAGS_WITH_VALUE, BOOLEAN_FLAGS } = await import('../skills/http-attack/scripts/lib/args.mjs');
  const flags = new Set([...HELP.matchAll(/^\s+(--[a-z-]+)/gm)].map((m) => m[1]));
  for (const f of flags) assert.ok(FLAGS_WITH_VALUE.has(f) || BOOLEAN_FLAGS.has(f), `${f} is in --help but not parsed`);
  for (const f of [...FLAGS_WITH_VALUE, ...BOOLEAN_FLAGS]) assert.ok(flags.has(f), `${f} is parsed but missing from --help`);
});

test('SKILL.md links every reference with one line, and each link points to a file', () => {
  const files = readdirSync(join(SKILL, 'references')).map((f) => f.replace(/\.md$/, '')).sort();
  const linked = [...skill.split('\n## References')[1].split('\n## ')[0].matchAll(/^- `references\/([a-z-]+)\.md`: .+$/gm)].map((m) => m[1]).sort();
  assert.deepEqual(linked, files);
  for (const section of ['Severity', 'What the script probes', 'Config file']) assert.ok(!skill.includes(`\n## ${section}\n`), `${section} lives in references/`);
});

test("README's flags table has a row for every flag the parser accepts, with its value and default", async () => {
  const { FLAGS_WITH_VALUE, BOOLEAN_FLAGS, parseArgs } = await import('../skills/http-attack/scripts/lib/args.mjs');
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  const rows = [...readme.split('\n## Flags')[1].split('\n## ')[0].matchAll(/^\| `(--[a-z-]+)` \| (.+?) \| (.+?) \| .+ \|$/gm)].map((m) => ({ flag: m[1], value: m[2], fallback: m[3] }));
  assert.deepEqual(rows.map((r) => r.flag).sort(), [...FLAGS_WITH_VALUE, ...BOOLEAN_FLAGS].sort());
  for (const r of rows) assert.equal(r.value === '-', BOOLEAN_FLAGS.has(r.flag), `${r.flag}: the value column is "-" exactly for flags without a value`);
  const { opt } = parseArgs(['http://127.0.0.1:1']);
  const defaults = { '--race-count': opt.raceCount, '--race-attempts': opt.raceAttempts, '--hang-ms': opt.hangMs, '--format': opt.format, '--origin-check': opt.originCheck };
  for (const [flag, value] of Object.entries(defaults)) assert.equal(rows.find((r) => r.flag === flag).fallback, `\`${value}\``, `${flag} default`);
});

test('every eval case grants only read tools and the Skill tool, in its frontmatter', () => {
  const root = join(import.meta.dirname, '..', 'evals');
  const cases = readdirSync(root).filter((n) => statSync(join(root, n)).isDirectory());
  assert.ok(cases.length >= 10);
  for (const name of cases) {
    const text = readFileSync(join(root, name, 'prompt.md'), 'utf8').replace(/\r\n/g, '\n');
    const front = text.match(/^---\n([\s\S]*?)\n---\n/)?.[1] ?? '';
    assert.match(front, /^allowed_tools: \[Read, Glob, Grep, Skill\]$/m, `${name}: allowed_tools`);
  }
});

test('no directory named "test" exists, because plain "node --test" would run every file in it', () => {
  const stray = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name === '.git') continue;
      if (e.name === 'test') stray.push(join(dir, e.name)); else walk(join(dir, e.name));
    }
  };
  walk(join(import.meta.dirname, '..'));
  assert.deepEqual(stray, []);
});
