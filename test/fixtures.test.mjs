import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { attackFixture } from './helpers/fixtures.mjs';

const expected = JSON.parse(readFileSync(new URL('./expected-vulnerable.json', import.meta.url), 'utf8'));

test('the fixed fixture has no finding and nothing is left unrun, three times in a row', async () => {
  for (let i = 0; i < 3; i++) {
    const r = await attackFixture('fixed');
    assert.deepEqual(r.ids, []);
    assert.equal(r.code, 0);
    assert.equal(r.report.summary.notRun, 0);
  }
});

test('the vulnerable fixture reports exactly the pinned set of finding ids', async () => {
  const r = await attackFixture('vulnerable');
  assert.equal(r.code, 1);
  assert.deepEqual(r.ids, [...expected].sort());
});
