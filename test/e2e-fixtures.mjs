// node test/e2e-fixtures.mjs [runs]: attacks both fixtures `runs` times (default 3) and fails unless the results are identical,
// the fixed fixture has no finding and the vulnerable one reports the pinned set of ids.
import { readFileSync } from 'node:fs';
import { attackFixture } from './helpers/fixtures.mjs';

const runs = Number(process.argv[2] ?? 3);
const expected = JSON.parse(readFileSync(new URL('./expected-vulnerable.json', import.meta.url), 'utf8'));
let failed = false;
const check = (ok, message) => { if (!ok) { failed = true; console.error(`FAIL ${message}`); } };

for (const kind of ['fixed', 'vulnerable']) {
  const results = [];
  for (let i = 0; i < runs; i++) results.push(await attackFixture(kind));
  const first = JSON.stringify(results[0].ids);
  check(results.every((r) => JSON.stringify(r.ids) === first), `${kind}: the ${runs} runs differ`);
  if (kind === 'fixed') {
    check(results.every((r) => r.code === 0 && r.ids.length === 0 && r.report.summary.notRun === 0), `fixed: expected exit 0 and no findings, got ${results.map((r) => `${r.code}/${r.ids.length}`)}`);
  } else {
    check(results[0].code === 1, `vulnerable: expected exit 1, got ${results[0].code}`);
    check(JSON.stringify(results[0].ids) === JSON.stringify([...expected].sort()),
      `vulnerable: finding ids differ. missing: ${expected.filter((i) => !results[0].ids.includes(i))}; unexpected: ${results[0].ids.filter((i) => !expected.includes(i))}`);
  }
  console.log(`${kind}: ${runs} runs, ${results[0].ids.length} findings, exit ${results[0].code}`);
}
process.exit(failed ? 1 : 0);
