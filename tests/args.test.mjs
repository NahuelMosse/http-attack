// Argument parsing without a server: what the parser accepts and what it rejects.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../skills/http-attack/scripts/lib/args.mjs';

const BASE = 'http://127.0.0.1:9';

test('--ignore is repeatable and takes comma-separated ids', () => {
  assert.deepEqual(parseArgs([BASE]).opt.ignore, []);
  const { opt } = parseArgs([BASE, '--ignore', 'not-run:idor', '--ignore', 'csrf, not-run:no-credentials,', '--ignore', 'server-error:*']);
  assert.deepEqual(opt.ignore, ['not-run:idor', 'csrf', 'not-run:no-credentials', 'server-error:*']);
});

test('--ignore needs a value', () => {
  assert.throws(() => parseArgs([BASE, '--ignore']), /--ignore needs a value/);
});
