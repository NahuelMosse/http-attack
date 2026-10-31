import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { tempDir } from './helpers/cli.mjs';
import { attackFixture, startFixture } from './helpers/fixtures.mjs';

const expected = JSON.parse(readFileSync(new URL('./expected-vulnerable.json', import.meta.url), 'utf8'));

test('the fixed fixture has no finding and nothing is left unrun, three times in a row', async () => {
  for (let i = 0; i < 3; i++) {
    const r = await attackFixture('fixed');
    assert.deepEqual(r.ids, []);
    assert.equal(r.code, 0);
    assert.equal(r.report.summary.notRun, 0);
  }
});

test('the fixed fixture answers an oversized body with 413 while the client is still sending, and keeps reading until it is done', async () => {
  const fixture = await startFixture('fixed', join(tempDir(), 'limit.db'));
  try {
    for (let i = 0; i < 3; i++) {
      const size = 4 << 20;
      const out = await new Promise((resolve) => {
        const req = request(`${fixture.url}/items`, { method: 'POST', agent: false, headers: { authorization: 'Bearer alice', 'content-type': 'application/json', 'content-length': size } });
        let status = null, sent = false, error = null;
        req.on('response', (res) => { status = res.statusCode; res.resume(); res.on('close', () => resolve({ status, sent, error })); });
        req.on('finish', () => { sent = true; });
        req.on('error', (e) => { error = e.code; resolve({ status, sent, error }); });
        req.end(Buffer.alloc(size, 97));
      });
      assert.deepEqual(out, { status: 413, sent: true, error: null }, `attempt ${i}`);
    }
  } finally { fixture.stop(); }
});

test('the vulnerable fixture reports exactly the pinned set of finding ids', async () => {
  const r = await attackFixture('vulnerable');
  assert.equal(r.code, 1);
  assert.deepEqual(r.ids, [...expected].sort());
});
