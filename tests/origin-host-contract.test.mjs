// Foreign Origin and Host, ambient credentials, the JSON switch and the OpenAPI status check: each against a server where the
// probe passes and one where it fails.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALICE, ITEM, attack, runCli, tempDir, writeTemp } from './helpers/cli.mjs';
import { startFixture } from './helpers/fixtures.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';
import { contractOf } from '../skills/http-attack/scripts/lib/openapi.mjs';

const withFixture = async (kind, fn) => {
  const f = await startFixture(kind, join(tempDir(), `${kind}.db`));
  try { return await fn(f); } finally { f.stop(); }
};
const withServer = async (quirks, fn) => {
  const s = await startQuirkServer(quirks);
  try { return await fn(s); } finally { await s.close(); }
};
const ORIGIN_PROBES = ['another-site', 'another-port', 'no-sec-fetch', 'null'].map((t) => `foreign-origin-${t}`);
const ROUTES = [...ALICE, '--write', ITEM, '--read', '/items?limit=10'];

test('--origin-check always: a foreign Origin is refused by the fixed fixture and accepted by the vulnerable one', async () => {
  await withFixture('fixed', async (f) => {
    const r = await attack(f.url, [...ROUTES, '--origin-check', 'always']);
    for (const p of ORIGIN_PROBES) assert.equal(r.row(`ok:${p}:POST /items`)?.verdict, 'pass', p);
    for (const p of ORIGIN_PROBES.slice(0, 2)) assert.equal(r.row(`ok:${p}:GET /items`)?.verdict, 'pass', p);
    assert.ok(!r.row('ok:foreign-origin-null:GET /items'), 'a read is attacked from another site and another port only');
  });
  await withFixture('vulnerable', async (f) => {
    const r = await attack(f.url, [...ROUTES, '--origin-check', 'always']);
    for (const p of ORIGIN_PROBES) assert.ok(r.has(`foreign-origin-accepted:${p}:POST /items`), p);
    assert.ok(r.has('foreign-origin-accepted:foreign-origin-another-site:GET /items'));
    assert.equal(r.row('foreign-origin-accepted:foreign-origin-another-site:POST /items').severity, 'high');
    const byDefault = await attack(f.url, ROUTES);
    assert.ok(!byDefault.report.rows.some((x) => x.group === 'origin'), 'the default (cookie) adds no origin row');
  });
});

test('--origin-check always: a 409/422 on a foreign Origin is NOT RUN, never a pass', () => withServer({ csrf422: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--origin-check', 'always']);
  assert.equal(r.row('not-run:foreign-origin-another-site:POST /items')?.verdict, 'not-run');
  assert.ok(r.report.summary.notRun >= 1);
}));

test('a foreign Host: refused passes, accepted is info by default and a finding with --strict-host', async () => {
  await withFixture('fixed', async (f) => {
    const r = await attack(f.url, [...ROUTES, '--strict-host']);
    assert.equal(r.row('ok:foreign-host:POST /items')?.verdict, 'pass');
    assert.equal(r.row('ok:foreign-host:GET /items')?.verdict, 'pass');
  });
  await withServer({}, async (s) => {
    const byDefault = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/items']);
    assert.ok(!byDefault.report.rows.some((x) => x.group === 'host'), 'the default adds no host row');
    assert.ok(!s.requests.some((q) => q.headers.host === 'attacker.example'), 'no foreign Host goes out by default');
    const r = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/items', '--host-check']);
    const info = r.row('info:foreign-host:POST /items');
    assert.equal(info?.verdict, 'info');
    assert.ok(!r.findings.some((id) => id.startsWith('foreign-host-accepted')));
    assert.equal(r.report.summary.info, 2);
    assert.ok(s.requests.some((q) => q.headers.host === 'attacker.example'), 'the Host header really went out');
    const strict = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/items', '--strict-host']);
    assert.ok(strict.has('foreign-host-accepted:foreign-host:POST /items'));
    assert.ok(strict.has('foreign-host-accepted:foreign-host:GET /items'));
    assert.equal(strict.code, 1);
  });
});

test('--no-ambient replaces the origin rows with one check: no Set-Cookie, no WWW-Authenticate', async () => {
  await withFixture('fixed', async (f) => {
    const r = await attack(f.url, [...ROUTES, '--no-ambient', '--origin-check', 'always']);
    assert.equal(r.row('ok:no-ambient:responses')?.verdict, 'pass');
    assert.ok(!r.report.rows.some((x) => x.probe.startsWith('foreign-origin')), 'the origin rows are replaced');
  });
  await withServer({ setCookie: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/items', '--no-ambient']);
    assert.ok(r.has('ambient-credentials:no-ambient:POST /items'));
    assert.ok(r.has('ambient-credentials:no-ambient:GET /items'));
  });
  const refused = await runCli(['http://127.0.0.1:9', '--no-ambient', '--csrf']);
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /--no-ambient/);
});

test('--json sends a form as JSON; without it a 415 to the form switches the write to JSON', () => withServer({}, async (s) => {
  const form = 'POST /items name=Ana&email=ana@example.com';
  const asJson = await attack(s.url, [...ALICE, '--write', form, '--json']);
  assert.equal(asJson.row('ok:legit-write:POST /items')?.verdict, 'pass');
  assert.equal(s.requests.find((q) => q.method === 'POST').headers['content-type'], 'application/json');
  const auto = await attack(s.url, [...ALICE, '--write', form, '--unique', 'POST /items name=Uno&email=uno@example.com']);
  const legit = auto.row('ok:legit-write:POST /items');
  assert.equal(legit?.verdict, 'pass');
  assert.match(legit.evidence, /415/);
  assert.equal(auto.row('ok:race-identical-creates:POST /items')?.verdict, 'pass', 'the race is retried as JSON');
  const noSwitch = await attack(s.url, [...ALICE, '--write', form, '--content-type', 'application/x-www-form-urlencoded']);
  assert.equal(noSwitch.row('not-run:legit-write:POST /items')?.verdict, 'not-run', 'a declared media type is never switched');
  const conflict = await runCli(['http://127.0.0.1:9', '--json', '--content-type', 'text/plain', '--write', form]);
  assert.equal(conflict.code, 2);
}));

test('--openapi: declared statuses pass, an undeclared one is a finding, an unreadable contract is NOT RUN', () => withServer({}, async (s) => {
  const dir = tempDir();
  const any = { responses: { '2XX': {}, '4XX': {} } };
  const loose = writeTemp(dir, 'loose.json', JSON.stringify({ openapi: '3.1.0', paths: { '/items': { get: any, post: any }, '/items/{id}': { get: any, delete: any } } }));
  const ok = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', loose]);
  assert.equal(ok.row('ok:openapi:responses')?.verdict, 'pass');
  assert.ok(!ok.findings.some((id) => id.startsWith('undocumented-status')));

  const strict = writeTemp(dir, 'strict.yaml', [
    'openapi: 3.1.0', 'paths:', '  /items:', '    post:', '      responses:', "        '201':", '          description: created',
    '        "400":', '          description: invalid', '  /items/{id}:', '    get:', '      responses:', '        200:', '          description: ok',
  ].join('\n'));
  assert.deepEqual(Object.fromEntries(Object.entries(contractOf(readFileSync(strict, 'utf8'))).map(([k, v]) => [k, [...v]])), { 'POST /items': ['201', '400'], 'GET /items/{id}': ['200'] });
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', strict]);
  assert.ok(r.has('undocumented-status:openapi-415:POST /items'), 'the 415 to a wrong media type is not declared');
  assert.ok(r.has('undocumented-status:openapi-401:GET /items/{id}'), 'the item read without credentials answered 401');
  assert.equal(r.row('undocumented-status:openapi-401:GET /items/{id}').severity, 'medium');

  const missing = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', join(dir, 'nope.yaml')]);
  assert.equal(missing.row('not-run:openapi:contract')?.verdict, 'not-run');
  assert.ok(missing.report.summary.notRun >= 1);
}));
