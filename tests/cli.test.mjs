// The command line contract: exit codes, argument validation, safety, the entry guard through a link, persistence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { ALICE, CLI, ITEM, ROOT, runCli, tempDir, writeTemp } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';
import { parseBase, toPath, unmangle } from '../skills/http-attack/scripts/lib/args.mjs';
import { exitCode, summarize } from '../skills/http-attack/scripts/lib/report.mjs';
import { checkPersistPath } from '../skills/http-attack/scripts/lib/probes/persist.mjs';
import { createClient } from '../skills/http-attack/scripts/lib/http.mjs';

const URL_ = 'http://127.0.0.1:9';

test('--help prints every option and exits 0', async () => {
  const r = await runCli(['--help']);
  assert.equal(r.code, 0);
  for (const flag of ['--write', '--fault-sqlite', '--config', '--auth-header-name', '--vary', '--content-type', '--race-count']) assert.match(r.stdout, new RegExp(flag));
  assert.doesNotMatch(r.stdout, /allow[-_]remote/i);
  assert.doesNotMatch(r.stdout, /--fault-cmd|--fault-restore/, 'shell commands are not accepted on the command line');
});

test('invalid invocations exit 2 with a message', async () => {
  const cases = [
    [[], /base URL/], [['http://['], /not a valid URL/], [['http://localhost:99999'], /not a valid URL/], [['ftp://localhost'], /base URL/],
    [[URL_, '--nope'], /Unknown option --nope/], [[URL_, '--allow-remote'], /Unknown option/], [[URL_, '--body-limit', 'abc'], /whole number/],
    [[URL_, '--body-limit'], /needs a value/], [[URL_, '--race-count', '1'], /between 2 and 64/], [[URL_, '--format', 'xml'], /text or json/],
    [[URL_, '--write', 'POST'], /wants/], [[URL_, '--header', 'nocolon'], /Name: value/], [[URL_, '--fault-cmd', 'x'], /Unknown option --fault-cmd/], [[URL_, '--fault-restore', 'x'], /Unknown option --fault-restore/],
    [[URL_, '--read', '/items?q=a b'], /not a valid request path/], [[URL_, '--search', '/ñ q'], /not a valid request path/],
    [['http://192.168.1.10:3000'], /not loopback/], [['http://localhost.attacker.com'], /not loopback/], [['http://127.0.0.1.nip.io'], /not loopback/],
    [[URL_, '--config', join(tempDir(), 'missing.json')], /cannot read the config/],
  ];
  for (const [args, message] of cases) {
    const r = await runCli(args);
    assert.equal(r.code, 2, `${args.join(' ')} -> ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, message);
  }
});

test('the remote override is an environment variable, not a flag', () => {
  assert.throws(() => parseBase('http://192.0.2.1:80', {}), /not loopback/);
  assert.equal(parseBase('http://192.0.2.1:80', { HTTP_ATTACK_ALLOW_REMOTE: '1' }).hostname, '192.0.2.1');
  assert.equal(parseBase('http://[::1]:3000', {}).hostname, '[::1]');
});

test('an app that does not answer exits 2', async () => {
  const s = await startQuirkServer();
  const url = s.url;
  await s.close();
  const r = await runCli([url]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /does not answer/);
});

test('invalid JSON in a body exits 2 and shows what arrived (PowerShell 5.1 strips the quotes)', async () => {
  const r = await runCli([URL_, '--write', 'POST /items {name:Ana,email:a@x.com}']);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /received: \{name:Ana,email:a@x\.com\}/);
  assert.match(r.stderr, /@body\.json/);
});

test('a malformed config exits 2: unknown key, ignore without a reason, unknown rule', async () => {
  const dir = tempDir();
  for (const [obj, message] of [
    [{ typo: 1 }, /unknown key "typo"/],
    [{ ignore: [{ id: 'server-error:x:y' }] }, /non-empty "reason"/],
    [{ ignore: [{ id: '*', reason: 'everything' }] }, /does not start with a known rule/],
    [{ ignore: [{ id: 'server-*', reason: 'x' }] }, /does not start with a known rule/],
    [{ public: true, reason: 'x' }, /only allowed inside "routes"/],
    [{ idempotentCreate: true }, /only allowed inside "routes"/],
    [{ routes: { '/a': { public: true } } }, /needs a non-empty "reason"/],
    [{ routes: { '/a': { idempotentCreate: true, reason: ' ' } } }, /needs a non-empty "reason"/],
    [{ faultRestore: 'x' }, /needs "faultCmd"/],
    [{ ignore: [{ id: 'not-a-rule:x', reason: 'r' }] }, /does not start with a known rule/],
    [{ ignore: [{ id: 'not-run', reason: 'r' }] }, /name the probe/],
    [{ ignore: [{ id: 'not-run:*', reason: 'r' }] }, /name the probe/],
    [{ routes: { '/a': { invalidUtf8: 'maybe' } } }, /reject.*replace/],
  ]) {
    const r = await runCli([URL_, '--config', writeTemp(dir, 'c.json', JSON.stringify(obj))]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, message);
  }
  const broken = await runCli([URL_, '--config', writeTemp(dir, 'bad.json', '{"a":')]);
  assert.equal(broken.code, 2);
  assert.match(broken.stderr, /not valid JSON, at (an unknown )?position/);
  assert.doesNotMatch(broken.stderr, /received/, 'the file content is not echoed');
  const secret = writeTemp(dir, 'secret.json', '{"token":"hunter2",}');
  const fromFile = await runCli([URL_, '--write', `POST /items @${secret}`]);
  assert.equal(fromFile.code, 2);
  assert.match(fromFile.stderr, /not valid JSON, at (an unknown )?position/);
  assert.doesNotMatch(fromFile.stderr, /hunter2/, 'a body file is never echoed');
  const viaConfig = await runCli([URL_, '--config', writeTemp(dir, 'cfg2.json', JSON.stringify({ writes: [{ path: '/items', body: `@${secret}` }] }))]);
  assert.equal(viaConfig.code, 2);
  assert.doesNotMatch(viaConfig.stderr, /hunter2/);
});

test('the Git Bash path rewrite is undone for --item-path and routes', () => {
  const env = { EXEPATH: 'C:\\Program Files\\Git' };
  assert.equal(unmangle('C:/Program Files/Git/items/{id}', env), '/items/{id}');
  assert.equal(toPath('C:\\Program Files\\Git\\items', env), '/items');
  assert.equal(unmangle('C:/msys64/items', {}), '/items');
  assert.equal(unmangle('items', env), 'items');
  assert.equal(toPath('items', env), '/items');
});

test('exit codes: findings 1, a clean run 0, no probe run or one not run 2', () => {
  const rows = (...verdicts) => verdicts.map((v) => ({ verdict: v, severity: v === 'fail' ? 'high' : undefined }));
  assert.equal(exitCode(summarize(rows('pass', 'pass'))), 0);
  assert.equal(exitCode(summarize(rows('pass', 'fail'))), 1);
  assert.equal(exitCode(summarize(rows('pass', 'not-run'))), 2);
  assert.equal(exitCode(summarize(rows())), 2);
  assert.equal(exitCode(summarize(rows('skipped'))), 2);
  assert.equal(exitCode(summarize([{ verdict: 'suppressed', was: 'fail' }, { verdict: 'pass' }])), 0);
});

test('the entry guard runs through a symlink or a junction', async () => {
  const dir = tempDir();
  const link = join(dir, 'linked-skill');
  symlinkSync(ROOT, link, 'junction');
  const viaDir = await runCli(['--help'], { entry: join(link, 'skills', 'http-attack', 'scripts', 'http-attack.mjs') });
  assert.equal(viaDir.code, 0);
  assert.match(viaDir.stdout, /usage: node http-attack\.mjs/);
  let fileLink = null;
  try { symlinkSync(CLI, join(dir, 'attack.mjs')); fileLink = join(dir, 'attack.mjs'); } catch { /* file symlinks need privileges on Windows */ }
  if (fileLink) {
    const viaFile = await runCli(['--help'], { entry: fileLink });
    assert.match(viaFile.stdout, /usage: node http-attack\.mjs/);
  }
  const noApp = await runCli(['http://127.0.0.1:9'], { entry: join(link, 'skills', 'http-attack', 'scripts', 'http-attack.mjs') });
  assert.equal(noApp.code, 2, 'a linked entry point still runs and still fails with 2, never silently with 0');
});

test('a connection cut after the headers settles instead of hanging', async () => {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-length': 100 });
    res.write('abc');
    setTimeout(() => res.socket.destroy(), 20);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const client = createClient(new URL(`http://127.0.0.1:${server.address().port}`), { headers: {}, otherHeaders: {}, authHeaderNames: [], common: [] });
    const res = await client.send('GET', '/');
    assert.equal(res.truncated, true);
    assert.equal(res.s, 200);
  } finally { server.closeAllConnections(); server.close(); }
});

test('persistence: save, verify, a missing file and volatile fields', async () => {
  const s = await startQuirkServer();
  const dir = tempDir();
  const file = join(dir, 'state.json');
  try {
    const saved = await runCli([s.url, ...ALICE, '--write', ITEM, '--persist-save', file]);
    assert.equal(saved.code, 0, saved.stderr + saved.stdout);
    const verified = await runCli([s.url, ...ALICE, '--persist-verify', file, '--format', 'json']);
    assert.equal(verified.code, 0);
    assert.equal(verified.json().schemaVersion, 1);
    assert.equal(verified.json().ok, true);
    const missing = await runCli([s.url, ...ALICE, '--persist-verify', join(dir, 'nope.json')]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /cannot read/);
    const state = JSON.parse((await import('node:fs')).readFileSync(file, 'utf8'));
    writeFileSync(file, JSON.stringify({ ...state, body: state.body.replace('Ana', 'Gone') }));
    const lost = await runCli([s.url, ...ALICE, '--persist-verify', file, '--format', 'json']);
    assert.equal(lost.code, 1);
    assert.equal(lost.json().id, 'not-durable:persist-verify:GET /items/{id}');
    assert.equal(lost.json().severity, 'critical');
    assert.equal(lost.json().ok, false);
    assert.match((await runCli([s.url, ...ALICE, '--persist-verify', file])).stdout, /FAIL critical/);
    writeFileSync(file, JSON.stringify({ ...state, body: JSON.stringify({ ...JSON.parse(state.body), stamp: 1 }) }));
    const ignoring = await runCli([s.url, ...ALICE, '--persist-verify', file, '--config', writeTemp(dir, 'c.json', '{"persistIgnore":["stamp"]}')]);
    assert.equal(ignoring.code, 0, 'a field named in persistIgnore is not compared');
  } finally { await s.close(); }
});


test('--persist-save never overwrites a file that is not a state file, and replaces its own', async () => {
  const s = await startQuirkServer();
  const dir = tempDir();
  try {
    const manifest = writeTemp(dir, 'package.json', '{"name":"app"}');
    const refused = await runCli([s.url, ...ALICE, '--write', ITEM, '--persist-save', manifest]);
    assert.equal(refused.code, 2);
    assert.match(refused.stderr, /not overwritten/);
    assert.equal(readFileSync(manifest, 'utf8'), '{"name":"app"}');
    assert.ok(!s.requests.some((q) => q.method === 'POST'), 'nothing was created before the refusal');
    const state = join(dir, 'state.json');
    assert.equal((await runCli([s.url, ...ALICE, '--write', ITEM, '--persist-save', state])).code, 0);
    const again = await runCli([s.url, ...ALICE, '--write', 'POST /items {"name":"Bea","email":"bea@example.com"}', '--persist-save', state]);
    assert.equal(again.code, 0, again.stderr);
    assert.match(readFileSync(state, 'utf8'), /Bea/);
  } finally { await s.close(); }
});

test('persist mode with the app down is a usage error, not a crash', async () => {
  const s = await startQuirkServer();
  const url = s.url;
  await s.close();
  const dir = tempDir();
  for (const args of [['--write', ITEM, '--persist-save', join(dir, 'state.json')], ['--persist-verify', writeTemp(dir, 'v.json', '{"item":"/items/1","status":200,"body":"{}"}')]]) {
    const r = await runCli([url, ...ALICE, ...args]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /does not answer/);
    assert.doesNotMatch(r.stderr, /crashed/);
  }
});

test('the state file of --persist-save must stay in the working directory or the temp directory unless the config allows its directory', async () => {
  const outside = join(homedir(), 'http-attack-forbidden', 'state.json');
  const r = await runCli([URL_, '--persist-verify', outside]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /outside the working directory.*persistDir/);
  const viaDotDot = await runCli([URL_, '--persist-verify', join(tempDir(), '..', '..', 'escape.json')]);
  assert.equal(viaDotDot.code, 2);
  assert.throws(() => checkPersistPath(outside, { persistDir: undefined }, tempDir()), /persistDir/);
  assert.doesNotThrow(() => checkPersistPath(outside, { persistDir: dirname(outside) }, tempDir()));
  assert.doesNotThrow(() => checkPersistPath(join(tempDir(), 'inside.json'), {}, process.cwd()));
});

test('credentials for user B identical to user A are refused', async () => {
  const same = await runCli([URL_, ...ALICE, '--other-header', 'Authorization: Bearer alice']);
  assert.equal(same.code, 2);
  assert.match(same.stderr, /same credentials as user A/);
});

test('an entry point whose path cannot be resolved still runs and never exits 0 silently', async () => {
  const href = pathToFileURL(CLI).href;
  const r = await new Promise((resolve) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(href)})`]);
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stderr }));
  });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /base URL/);
});
