// A body that never ends in both framings, HEAD on a write-only route, and a race whose successes redirect.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ALICE, ITEM, attack } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';

const withServer = async (quirks, fn) => {
  const s = await startQuirkServer(quirks);
  try { return await fn(s); } finally { await s.close(); }
};
const LIMIT = ['--body-limit', String(3 << 20)];

test('with a declared limit, a never-ending body cut by a reset instead of a 413 is a finding', () => withServer({ streamLimit: 3 << 20, streamReset: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, ...LIMIT]);
  assert.ok(r.has('connection-dropped:body-never-ends:POST /items'));
  assert.ok(r.has('connection-dropped:body-never-ends-length:POST /items'));
}));

test('a never-ending body with a Content-Length that does not arrive: read forever fails, a 413 passes', async () => {
  await withServer({}, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.ok(r.has('no-body-limit:body-never-ends-length:POST /items'));
    assert.ok(s.requests.some((q) => q.headers['content-length'] === String(100 << 20)), 'the large Content-Length really went out');
  });
  await withServer({ streamLimit: 3 << 20 }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM, ...LIMIT]);
    assert.equal(r.row('ok:body-never-ends-length:POST /items')?.verdict, 'pass');
    assert.equal(r.row('ok:body-never-ends:POST /items')?.verdict, 'pass');
  });
});

test('HEAD goes to a write-only route too: a 405 with Allow passes, a 5xx fails', async () => {
  await withServer({}, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.equal(r.row('ok:head:HEAD /items')?.verdict, 'pass');
    assert.ok(!r.findings.some((id) => id.startsWith('head-unsupported')), 'a write-only route may refuse HEAD');
  });
  await withServer({ head500: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.ok(r.has('server-error:head:HEAD /items'));
  });
});

test('a race whose successes redirect (POST/redirect/GET) is judged like 2xx successes', async () => {
  const unique = ['--unique', 'POST /things {"key":"k"}'];
  await withServer({ storedDuplicates: true, prg: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, ...unique]);
    assert.ok(r.has('duplicates-stored:race-identical-creates:POST /things'));
  });
  await withServer({ idempotentCreate: true, prg: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, ...unique]);
    assert.equal(r.row('ok:race-identical-creates:POST /things')?.verdict, 'pass');
  });
});

test('a race of one 201 and 302s back to the form or to the same item is one create', async () => {
  for (const mode of [true, 'bare-item', 'bare-form', 'absolute']) {
    await withServer({ conflictRedirect: mode }, async (s) => {
      const r = await attack(s.url, [...ALICE, '--unique', 'POST /things {"sku":"k"}']);
      assert.equal(r.row('ok:race-identical-creates:POST /things')?.verdict, 'pass', String(mode));
    });
  }
});

test('with a declared limit, a never-ending body refused with a 4xx other than 413 is a finding', () => withServer({ streamLimit: 3 << 20, streamStatus: 400 }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, ...LIMIT]);
  assert.ok(r.has('no-body-limit:body-never-ends:POST /items'));
}));

test('HEAD on a write-only route answered 405 without Allow fails and does not pass', () => withServer({ noHead: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(r.has('missing-allow:head:HEAD /items'));
  assert.equal(r.row('ok:head:HEAD /items'), undefined);
}));
