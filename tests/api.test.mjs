// The programmatic entry: `attack(argv)` returns the report instead of printing or exiting.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ALICE, ITEM } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';
import * as entry from '../skills/http-attack/scripts/index.mjs';

test('attack() resolves to the report, with --ignore applied and the exit code', async () => {
  const s = await startQuirkServer({});
  try {
    const report = await entry.attack([s.url, '--hang-ms', '600', ...ALICE, '--write', ITEM, '--ignore', 'not-run:idor,not-run:csrf']);
    assert.equal(report.base, s.url);
    assert.ok(report.rows.length > 10);
    assert.ok([0, 1, 2].includes(report.exitCode));
    assert.equal(report.rows.find((r) => r.id === 'not-run:idor')?.verdict, 'suppressed');
    assert.match(entry.renderJson(report), /"schemaVersion": 1/);
    assert.match(entry.renderText(report), /pass/);
  } finally { await s.close(); }
});

test('attack() rejects usage problems and the command-line-only modes', async () => {
  await assert.rejects(entry.attack(['http://127.0.0.1:9', '--nope']), /Unknown option --nope/);
  await assert.rejects(entry.attack(['--help']), /command line/);
  await assert.rejects(entry.attack(['http://127.0.0.1:9', '--persist-save', 'state.json']), /command line/);
  await assert.rejects(entry.attack(['http://127.0.0.1:9']), /does not answer/);
});
