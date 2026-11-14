// --unique also sends a twin whose unique field differs only in letter case: a key unique ignoring case answers it 409, never
// a 5xx; a key that stores both fails its own row (`race-case-twin`), apart from the identical race.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { attack } from './helpers/cli.mjs';

const bodyOf = async (req) => { let t = ''; for await (const c of req) t += c; return t; };

// `fold`: the key is unique ignoring case; `crash`: storing a folded duplicate throws.
const start = ({ fold, crash }) => new Promise((ready) => {
  const seen = new Set();
  const server = createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/u') { res.writeHead(req.url === '/' ? 200 : 404); return res.end(); }
    const raw = new URLSearchParams(await bodyOf(req)).get('name') ?? '';
    const key = fold ? raw.toLowerCase() : raw;
    if (seen.has(key)) { res.writeHead(crash ? 500 : 409); return res.end(); }
    seen.add(key);
    res.writeHead(201); res.end();
  });
  server.listen(0, '127.0.0.1', () => ready({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((d) => server.close(d)) }));
});
const withServer = async (opts, fn) => { const s = await start(opts); try { return await fn(s); } finally { await s.close(); } };
const UNIQUE = ['--unique', 'POST /u name=Ana'];

test('a key unique ignoring case passes the case twin', () => withServer({ fold: true }, async (s) => {
  const r = await attack(s.url, UNIQUE);
  assert.equal(r.row('ok:race-case-twin:POST /u')?.verdict, 'pass');
  assert.ok(!r.has('duplicates-stored:race-identical-creates:POST /u'));
}));

test('a key that stores both cases fails the twin row, not the identical race', () => withServer({ fold: false }, async (s) => {
  const r = await attack(s.url, UNIQUE);
  assert.ok(r.has('duplicates-stored:race-case-twin:POST /u'));
  assert.ok(!r.has('duplicates-stored:race-identical-creates:POST /u'));
}));

test('a 5xx on the case twin is a server-error row', () => withServer({ fold: true, crash: true }, async (s) => {
  const r = await attack(s.url, UNIQUE);
  assert.ok(r.has('server-error:race-case-twin:POST /u'));
}));
