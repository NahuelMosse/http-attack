// Edge cases of the origin, host, ambient, JSON, OpenAPI and leak probes: each against a server where the wrong reading
// would give another verdict.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { ALICE, ITEM, attack, tempDir, writeTemp } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';
import { renderText, summarize } from '../skills/http-attack/scripts/lib/report.mjs';

const withServer = async (quirks, fn) => {
  const s = await startQuirkServer(quirks);
  try { return await fn(s); } finally { await s.close(); }
};
const contract = (dir, name, paths, prefix = '') => writeTemp(dir, name, prefix + JSON.stringify({ openapi: '3.1.0', paths }));
const ANY = { responses: { '2XX': {}, '4XX': {} } };
const LOOSE = { '/items': { get: ANY, post: ANY }, '/items/{id}': { get: ANY } };

test('a read whose legitimate request answers 401 gets no origin or host row: they would prove nothing', () => withServer({ basicRead: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/private', '--origin-check', 'always', '--host-check']);
  assert.equal(r.row('not-run:legit-read:GET /private')?.verdict, 'not-run');
  assert.ok(!r.report.rows.some((x) => x.target === 'GET /private' && ['origin', 'host'].includes(x.group) && x.probe !== 'legit-read'));
}));

test('--no-ambient looks at every answered response: a 401 asking WWW-Authenticate is ambient', () => withServer({ basicRead: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/private', '--no-ambient']);
  assert.ok(r.has('ambient-credentials:no-ambient:GET /private'));
  assert.match(r.row('ambient-credentials:no-ambient:GET /private').evidence, /www-authenticate/);
}));

test('--no-ambient: a 403 asking WWW-Authenticate Bearer is not ambient', () => withServer({ bearerScope: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/private', '--no-ambient']);
  assert.ok(!r.findings.some((id) => id.startsWith('ambient-credentials')));
}));

test('--openapi reads a file under a directory named git, and a contract that starts with a BOM', () => withServer({}, async (s) => {
  const dir = join(tempDir(), 'git');
  mkdirSync(dir);
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', contract(dir, 'api.json', LOOSE)]);
  assert.equal(r.row('ok:openapi:responses')?.verdict, 'pass');
  const bom = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', contract(tempDir(), 'bom.json', LOOSE, '﻿')]);
  assert.equal(bom.row('ok:openapi:responses')?.verdict, 'pass');
}));

test('--openapi: a `default` response documents every status', () => withServer({}, async (s) => {
  const any = { responses: { default: {} } };
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', contract(tempDir(), 'default.json', { '/items': { get: any, post: any }, '/items/{id}': { get: any } })]);
  assert.equal(r.row('ok:openapi:responses')?.verdict, 'pass');
}));

test('--openapi judges a path by the most specific template that matches it', () => withServer({}, async (s) => {
  const file = contract(tempDir(), 'specific.json', { '/{a}/{b}': { get: { responses: { 599: {} } } }, ...LOOSE });
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--openapi', file]);
  assert.ok(!r.has('undocumented-status:openapi-200:GET /{a}/{b}'), 'the item read is judged by /items/{id}');
  assert.equal(r.row('ok:openapi:responses')?.verdict, 'pass');
}));

test('--openapi sees the race answers: a 2xx-only contract flags the 409 of the identical creates', () => withServer({}, async (s) => {
  const file = contract(tempDir(), 'created.json', { '/items': { post: { responses: { '2XX': {}, 400: {}, 413: {}, 415: {} } } } });
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--unique', ITEM.replace('Ana', 'Uno').replace('ana@', 'uno@'), '--openapi', file]);
  assert.ok(r.has('undocumented-status:openapi-409:POST /items'));
}));

test('a 413 answered to a streamed body without the common headers is a finding', () => withServer({ streamLimit: 3 << 20, bare413: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--body-limit', String(3 << 20), '--common-headers', 'x-request-id']);
  assert.ok(r.has('headers-missing:common-headers:POST /items'));
  assert.match(r.row('headers-missing:common-headers:POST /items').got, /413/);
}));

test('--json converts the form bodies of the config writes too', () => withServer({}, async (s) => {
  const dir = tempDir();
  const config = writeTemp(dir, 'http-attack.config.json', JSON.stringify({ writes: [{ method: 'POST', path: '/items', body: 'name=Ana&email=ana@example.com' }] }));
  const r = await attack(s.url, [...ALICE, '--json', '--config', config]);
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
  assert.equal(s.requests.find((q) => q.method === 'POST').headers['content-type'], 'application/json');
}));

test('--json with --content-type application/json accepts a form write: it is converted before the body is checked', () => withServer({}, async (s) => {
  const r = await attack(s.url, [...ALICE, '--json', '--content-type', 'application/json', '--write', 'POST /items name=Ana&email=ana@example.com']);
  assert.equal(r.stderr, '');
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
  assert.notEqual(r.code, 2, 'not a usage error');
}));

test('--json converts a config write declared as application/json before its body is checked', () => withServer({}, async (s) => {
  const config = writeTemp(tempDir(), 'http-attack.config.json', JSON.stringify({ writes: [{ method: 'POST', path: '/items', contentType: 'application/json', body: 'name=Ana&email=ana@example.com' }] }));
  const r = await attack(s.url, [...ALICE, '--json', '--config', config]);
  assert.notEqual(r.code, 2, r.stderr);
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
}));

test('--leak-path is repeatable: a 2xx with the file is a finding, a 404 passes', () => withServer({ leak: '/secret.txt' }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--leak-path', '/secret.txt', '--leak-path', '/missing.txt']);
  assert.ok(r.has('file-served:file-served:GET /secret.txt'));
  assert.equal(r.row('ok:file-served:GET /missing.txt')?.verdict, 'pass');
}));

test('renderText prints a verdict it does not know instead of crashing', () => {
  const rows = [{ id: 'x:y:z', group: 'g', probe: 'y', target: 'z', name: 'a row', verdict: 'weird', got: '1', expected: 'e' }];
  const text = renderText({ rows, summary: summarize(rows), unusedIgnores: [] });
  assert.match(text, /^weird\s+1\s+\[g\] a row/);
});

test('a failed legitimate write makes its host rows NOT RUN only when a Host flag is on', () => withServer({}, async (s) => {
  const bad = 'POST /items {"name":1}';
  const off = await attack(s.url, [...ALICE, '--write', bad]);
  assert.ok(!off.report.rows.some((x) => x.group === 'host'));
  const on = await attack(s.url, [...ALICE, '--write', bad, '--host-check']);
  assert.equal(on.row('not-run:host-probes:POST /items')?.verdict, 'not-run');
}));

test('a foreign Host answered 409 or 422 is the body refused: NOT RUN, never a pass', async () => {
  for (const status of [422, 409]) {
    await withServer({ hostValidates: status }, async (s) => {
      const r = await attack(s.url, [...ALICE, '--write', ITEM, '--host-check']);
      assert.equal(r.row('not-run:foreign-host:POST /items')?.verdict, 'not-run', String(status));
    });
  }
});

test('a foreign Origin answered 400 is the body refused: NOT RUN, never a pass', () => withServer({ origin400: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--origin-check', 'always']);
  assert.equal(r.row('not-run:foreign-origin-another-site:POST /items')?.verdict, 'not-run');
}));

test('an origin probe whose connection is reset once is repeated, not reported as a dropped connection', () => withServer({ resetFirstOrigin: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--origin-check', 'always']);
  assert.ok(r.has('foreign-origin-accepted:foreign-origin-another-site:POST /items'));
  assert.ok(!r.findings.some((id) => id.startsWith('connection-dropped:foreign-origin')));
}));
