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

test('every pinned id of the vulnerable fixture is explained by a defect in its header, and every defect has an id', () => {
  const header = readFileSync(new URL('../skills/http-attack/fixtures/vulnerable-server.mjs', import.meta.url), 'utf8').split('\n').filter((l) => l.startsWith('//'));
  const defects = new Map();
  let current = null;
  for (const line of header) {
    const defect = line.match(/^\/\/ \[(D\d+)\] \S/);
    if (defect) { current = defect[1]; defects.set(current, []); continue; }
    const id = line.match(/^\/\/\s+id: (\S.*)$/);
    if (id) { assert.ok(current, `${id[1]} is listed before any defect`); defects.get(current).push(id[1]); }
  }
  for (const [defect, ids] of defects) assert.ok(ids.length > 0, `${defect} produces no id`);
  const listed = [...defects.values()].flat();
  assert.equal(new Set(listed).size, listed.length, 'an id is listed under two defects');
  assert.deepEqual([...listed].sort(), [...expected].sort());
});

test('the vulnerable fixture reports exactly the pinned set of finding ids', async () => {
  const r = await attackFixture('vulnerable');
  assert.equal(r.code, 1);
  assert.deepEqual(r.ids, [...expected].sort());
});
