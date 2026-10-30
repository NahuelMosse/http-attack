#!/usr/bin/env node
// http-attack.mjs: adversarial probes against a running HTTP API on this machine. Node 22.5+ built-ins only.
//
//   node http-attack.mjs <base-url> [options]
//
//   --write "<METHOD> <path> <body>"  an endpoint that creates or changes state, with a legitimate body (JSON if it starts with
//                                     { or [, else a form a=1&b=2). Repeatable. The first one is also used by --fault-sqlite.
//   --read "<path>"                   an endpoint that returns data, with its query if any (?limit=10). Repeatable.
//   --search "<path> <param>"         a read with a free-text search parameter. Repeatable.
//   --unique "<METHOD> <path> <body>" a create guarded by a unique key: 8 identical requests are sent at once.
//   --fault-sqlite <file>             the app's SQLite file: holds BEGIN EXCLUSIVE while the first --write is sent.
//   --header "Name: value"            sent on every request (credentials of user A). Repeatable.
//   --auth-env <VAR>                  sends "Authorization: Bearer $VAR" without putting the token in the command line.
//   --other-header "Name: value"      credentials of a second user B, for the ownership (IDOR) rows. Repeatable.
//   --item-path "/items/{id}"         where a created item is read, when the create answers no Location (the id comes from the JSON body).
//   --common-headers "A, B"           headers every response must carry, parser errors included.
//   --raw-exempt "<why>"              raw parser errors are answered by a proxy or server before the app: do not check common headers there.
//   --body-limit <bytes>              the documented body limit: one byte over (multibyte) must be 413.
//   --csrf                            the app authenticates with cookies: cross-origin writes must be refused.
//   --persist-save <file>             create one item through the first --write and save how to read it back, then stop.
//   --persist-verify <file>           after a restart, read the saved item back and compare it.
//   --format json                     one JSON object instead of the text table.
//   --allow-remote                    run against a host that is not loopback. Only for a host you own.
//
// Exit codes: 0 nothing failed · 1 at least one finding · 2 the app did not answer or a probe could not run.
import { request } from 'node:http';
import { connect } from 'node:net';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

// Resolved exactly as the app's own node process resolves its argument, so the same string reaches the same file.
// Git Bash rewrites "/tmp/x.db" for both processes, unless MSYS_NO_PATHCONV=1 is set, in which case node.exe reads
// it against the drive root for both. Translating here would make the two disagree.
const resolveFsPath = (p) => resolvePath(p);

const args = process.argv.slice(2);
const usage = (why) => { console.error(`${why}\nusage: node http-attack.mjs <base-url> [--write "POST /items {...}"] [--read "/items"] [--search "/items q"] [--unique "POST /items {...}"] [--fault-sqlite file] [--header "K: v"] [--other-header "K: v"] [--common-headers "A, B"] [--body-limit n] [--format json]`); process.exit(2); };
if (!/^https?:\/\//.test(args[0] ?? '')) usage('The first argument is the base URL.');
const base = new URL(args[0]);
if (base.protocol !== 'http:') usage('Only plain http is supported: probe the app behind its TLS terminator.');

// Git Bash rewrites "/path" to a Windows path; a path given without the leading slash is also accepted.
const unmangle = (r) => String(r).replace(/^[A-Za-z]:[\\/].*?[\\/]Git[\\/]/, '/');
const toPath = (r) => '/' + unmangle(r).replace(/^\/+/, '');
const opt = { writes: [], reads: [], searches: [], uniques: [], common: [], extra: {}, other: {}, allowRemote: false, csrf: false, bodyLimit: 0, json: false };
const headerInto = (target, line) => {
  const at = line.indexOf(':');
  const key = line.slice(0, at).trim().toLowerCase();
  if (at < 1 || !/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(key)) usage(`Not a header: "${line}".`);
  target[key] = line.slice(at + 1).trim();
};
const splitRequest = (s, flag) => {
  const [method, r, ...body] = String(s ?? '').split(' ');
  if (!method || !r) usage(`${flag} wants "<METHOD> <path> <body>".`);
  return { method: method.toUpperCase(), path: toPath(r), body: body.join(' ') };
};
for (let i = 1; i < args.length; i++) {
  const a = args[i], v = () => args[++i] ?? '';
  if (a === '--write') opt.writes.push(splitRequest(v(), a));
  else if (a === '--unique') opt.uniques.push(splitRequest(v(), a));
  else if (a === '--read') opt.reads.push(toPath(v()));
  else if (a === '--search') { const [r, p] = unmangle(v()).split(' '); if (!r || !p) usage('--search wants "<path> <param>".'); opt.searches.push({ path: toPath(r), param: p }); }
  else if (a === '--fault-sqlite') opt.fault = v();
  else if (a === '--header') headerInto(opt.extra, v());
  else if (a === '--other-header') headerInto(opt.other, v());
  else if (a === '--auth-env') { const n = v(); if (!process.env[n]) usage(`--auth-env ${n}: the variable is empty.`); opt.extra.authorization = `Bearer ${process.env[n]}`; }
  else if (a === '--item-path') opt.itemPath = v();
  else if (a === '--common-headers') opt.common = v().split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  else if (a === '--raw-exempt') opt.rawExempt = v();
  else if (a === '--body-limit') { opt.bodyLimit = Number(v()); if (!Number.isInteger(opt.bodyLimit) || opt.bodyLimit < 16) usage('--body-limit wants a whole number of bytes, 16 or more.'); }
  else if (a === '--csrf') opt.csrf = true;
  else if (a === '--persist-save') opt.persistSave = v();
  else if (a === '--persist-verify') opt.persistVerify = v();
  else if (a === '--format') opt.json = v() === 'json';
  else if (a === '--allow-remote') opt.allowRemote = true;
  else usage(`Unknown option ${a}.`);
}
const LOOPBACK = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|[\w-]+\.localhost)$/i;
if (!LOOPBACK.test(base.hostname) && !opt.allowRemote) usage(`${base.hostname} is not loopback. These probes are destructive: run them only against a server you own (add --allow-remote for that).`);

// ---------- transport ----------
const FORM = 'application/x-www-form-urlencoded';
const isJson = (body) => opt.json || /^\s*[{[]/.test(body);
const rows = [];
let pending = []; // responses that lacked a common header, attached to the next row pushed
const checkCommon = (what, headers) => { for (const h of opt.common) if (headers?.[h] === undefined) pending.push(`${what} lacks ${h}`); };
const row = (r) => {
  if (pending.length) {
    r.evidence = [r.evidence, ...pending].filter(Boolean).join('; ');
    if (r.verdict === 'pass') Object.assign(r, { verdict: 'fail', severity: 'medium', expected: `${r.expected}; every response carries ${opt.common.join(', ')}` });
    pending = [];
  }
  rows.push(r);
};
const pass = (group, name, got, expected) => row({ group, name, verdict: 'pass', got, expected });
const fail = (group, name, severity, got, expected, evidence) => row({ group, name, verdict: 'fail', severity, got, expected, evidence });
const notRun = (group, name, why) => row({ group, name, verdict: 'not-run', expected: '', evidence: why });

// One request with node:http (fetch cannot send a path starting with //, nor stream a slow body).
// auth: 'a' (default headers), 'none' (credentials removed), 'b' (the other user's headers).
const send = (method, path, { body, type, headers = {}, auth = 'a', common = true } = {}) => new Promise((done) => {
  const data = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(body);
  const creds = auth === 'b' ? { ...strip(opt.extra), ...opt.other } : auth === 'none' ? strip(opt.extra) : opt.extra;
  const all = { ...creds, ...(data ? { 'content-length': data.length, ...(type ? { 'content-type': type } : {}) } : {}), ...headers };
  const req = request({ hostname: base.hostname, port: base.port || 80, path, method, agent: false,
    headers: Object.fromEntries(Object.entries(all).filter(([, v]) => v !== undefined)) }, (res) => {
    let text = '';
    res.on('data', (d) => { if (text.length < 200_000) text += d; });
    res.on('end', () => { if (common) checkCommon(`${method} ${path} → ${res.statusCode}`, res.headers); done({ s: res.statusCode, headers: res.headers, text }); });
  });
  req.setTimeout(10_000, () => req.destroy(new Error('timeout')));
  req.on('error', (e) => done({ s: null, err: e.code ?? e.message, headers: {}, text: '' }));
  req.end(data ?? undefined);
});
const strip = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => !['authorization', 'cookie', 'x-api-key'].includes(k)));
const alive = async () => (await send('GET', '/', { common: false })).s !== null;
const is4xx = (s) => s >= 400 && s < 500;
const is2xx = (s) => s >= 200 && s < 300;

// The legitimate body of a write, with the field that keeps requests apart suffixed (`-<run><n>`, before the @ of an email),
// so a uniqueness rule never answers in place of the defense under test, in this run or the next.
let counter = 0;
const RUN = Date.now().toString(36).slice(-5);
const FORMATTED = /^[^\p{L}]*$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const vary = (entries, n) => {
  const free = (v) => typeof v === 'string' && !FORMATTED.test(v);
  const key = entries.find(([, v]) => free(v) && v.includes('@'))?.[0] ?? entries.find(([, v]) => free(v))?.[0];
  const tag = `-${RUN}${n}`;
  return entries.map(([k, v]) => [k, k === key ? (v.includes('@') ? v.replace('@', `${tag}@`) : `${v}${tag}`) : v]);
};
const wire = (body, n = ++counter) => {
  if (!isJson(body)) return { text: new URLSearchParams(vary([...new URLSearchParams(body)], n)).toString(), type: FORM };
  let f; try { f = /^\s*[{[]/.test(body) ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body)); } catch { return { text: body, type: 'application/json' }; }
  const out = f && typeof f === 'object' && !Array.isArray(f) ? Object.fromEntries(vary(Object.entries(f), n)) : f;
  return { text: JSON.stringify(out), type: 'application/json' };
};

// ---------- probes ----------
// A legitimate write, and where the item it created can be read back.
const itemUrlOf = (res) => {
  if (res.headers.location) { try { const u = new URL(res.headers.location, base); return u.pathname + u.search; } catch { /* not a URL */ } }
  if (!opt.itemPath) return null;
  try { const id = JSON.parse(res.text)?.id; return id === undefined ? null : opt.itemPath.replace('{id}', encodeURIComponent(id)); } catch { return null; }
};

const malformedInput = async (w) => {
  const g = 'input';
  const json = isJson(w.body);
  const probe = async (name, res, okWhen, expected, sev = 'high') => {
    if (res.s === null) return fail(g, name, 'critical', res.err, expected, (await alive()) ? 'connection dropped' : 'the app stopped answering');
    if (okWhen(res.s)) return pass(g, name, res.s, expected);
    fail(g, name, res.s >= 500 ? 'high' : sev, res.s, expected);
  };
  if (json) await probe(`${w.method} ${w.path} malformed JSON`, await send(w.method, w.path, { body: '{"x":', type: 'application/json' }), (s) => s === 400 || s === 422, '400 with the error body');
  if (json) {
    let f; try { f = JSON.parse(wire(w.body).text); } catch { f = {}; }
    if (!f || typeof f !== 'object' || Array.isArray(f)) f = {};
    f[Object.keys(f).find((k) => typeof f[k] === 'string') ?? 'x'] = 'MARKER';
    const [head, tail] = JSON.stringify(f).split('MARKER');
    const bytes = Buffer.concat([Buffer.from(head), Buffer.from([0xc3, 0x28, 0xff]), Buffer.from(tail)]);
    await probe(`${w.method} ${w.path} invalid UTF-8 inside a string`, await send(w.method, w.path, { body: bytes, type: 'application/json' }), is4xx, '400: strict UTF-8 decoding, nothing stored with U+FFFD');
    await probe(`${w.method} ${w.path} JSON without a content-type`, await send(w.method, w.path, { body: wire(w.body).text }), (s) => s < 500, '415 (never a 5xx from reading a missing header)');
    const cs = await send(w.method, w.path, { body: wire(w.body).text, type: 'Application/JSON; charset=utf-8' });
    if (cs.s === 415) fail(g, `${w.method} ${w.path} Application/JSON; charset=utf-8`, 'medium', 415, 'accepted as JSON: media types are case-insensitive and may carry parameters (RFC 9110 8.3.1)');
    else await probe(`${w.method} ${w.path} Application/JSON; charset=utf-8`, cs, (s) => s < 500, 'accepted as JSON');
    for (const [label, value] of [['a number', 1], ['null', null], ['an array', ['a']], ['an object', { a: 1 }]]) {
      let f; try { f = JSON.parse(wire(w.body).text); } catch { break; }
      const key = Object.keys(f).find((k) => typeof f[k] === 'string');
      if (!key) break;
      f[key] = value;
      await probe(`${w.method} ${w.path} "${key}" sent as ${label}`, await send(w.method, w.path, { body: JSON.stringify(f), type: 'application/json' }), (s) => s === 400 || s === 422, '400/422: wrong type, never coerced, never a 5xx');
    }
  }
  await probe(`${w.method} ${w.path} 1 MB body`, await send(w.method, w.path, { body: json ? JSON.stringify({ x: 'a'.repeat(1 << 20) }) : 'x=' + 'a'.repeat(1 << 20), type: json ? 'application/json' : FORM }), is4xx, '413 (or 400), never stored and never a 5xx');
  if (opt.bodyLimit && json) {
    let f; try { f = JSON.parse(wire(w.body).text); } catch { f = { x: '' }; }
    const key = Object.keys(f).find((k) => typeof f[k] === 'string') ?? 'x';
    f[key] = '';
    const rest = Buffer.byteLength(JSON.stringify(f));
    f[key] = 'é'.repeat(Math.floor((opt.bodyLimit - rest) / 2) + 1);
    const text = JSON.stringify(f);
    const name = `${w.method} ${w.path} body 1+ byte over the limit (multibyte: ${[...text].length} chars, ${Buffer.byteLength(text)} bytes)`;
    const r = await send(w.method, w.path, { body: text, type: 'application/json' });
    if (r.s === 413) pass(g, name, 413, '413: the limit counts bytes, not characters'); else fail(g, name, r.s >= 500 || r.s === null ? 'high' : 'medium', r.s ?? r.err, '413: the limit counts bytes, not characters');
  }
  for (const m of ['PUT', 'DELETE', 'PATCH'].filter((x) => x !== w.method)) await probe(`${m} ${w.path} (method the route does not take)`, await send(m, w.path, { body: wire(w.body).text, type: wire(w.body).type }), is4xx, '405 with Allow (or 404)', 'high');
};

// A body that keeps coming: a server without a limit or timeout reads it forever.
const HANG_MS = Number(process.env.HTTP_ATTACK_HANG_MS ?? 6000);
const stream = (method, path, headers, total, pieceSize, { stopAfterMs }) => new Promise((done) => {
  const req = request({ hostname: base.hostname, port: base.port || 80, path, method, agent: false, headers: { ...opt.extra, ...headers } });
  const piece = Buffer.alloc(pieceSize, 97);
  const t0 = Date.now();
  let sent = 0, over = false, timer;
  const finish = (v) => { if (over) return; over = true; clearInterval(pump); clearTimeout(timer); req.destroy(); done({ ...v, sent, ms: Date.now() - t0 }); };
  const pump = setInterval(() => {
    if (sent >= total) { clearInterval(pump); timer = setTimeout(() => finish({ kind: 'silent' }), stopAfterMs); return; }
    if (req.writableNeedDrain) return;
    req.write(sent === 0 && headers['content-type'] === 'application/json' ? Buffer.concat([Buffer.from('{"x":"'), piece]) : piece);
    sent += piece.length;
  }, 5);
  req.on('response', (res) => { res.resume(); checkCommon(`${method} ${path} → ${res.statusCode}`, res.headers); finish({ kind: 'status', s: res.statusCode }); });
  req.on('error', (e) => finish({ kind: 'closed', code: e.code ?? e.message }));
  req.on('close', () => finish({ kind: 'closed', code: 'closed' }));
});
const resources = async (w) => {
  const g = 'resources';
  if (!isJson(w.body)) return;
  const BIG = 50 << 20;
  let v = await stream(w.method, w.path, { 'content-type': 'text/plain', 'content-length': BIG }, BIG, 64 << 10, { stopAfterMs: 3000 });
  let name = `${w.method} ${w.path} 50 MB text/plain body`;
  const exp = '415 (or 413) at the first bytes, before reading the body';
  const up = await alive();
  if (!up) fail(g, name, 'critical', v.s ?? v.code, exp, 'the app stopped answering');
  else if (v.kind === 'status' && is4xx(v.s) && (v.sent < BIG || v.ms < 2000)) pass(g, name, v.s, exp);
  else if (v.kind === 'status' && is4xx(v.s)) fail(g, name, 'medium', v.s, exp, `answered only after reading all 50 MB (${v.ms} ms)`);
  else if (v.kind === 'closed' && v.sent < BIG) pass(g, name, 'closed', exp);
  else fail(g, name, 'high', v.s ?? v.kind, exp, `${(v.sent / 2 ** 20).toFixed(1)} MB sent`);

  v = await stream(w.method, w.path, { 'content-type': 'application/json', 'transfer-encoding': 'chunked' }, 2 << 20, 16 << 10, { stopAfterMs: HANG_MS });
  name = `${w.method} ${w.path} JSON body that never ends (chunked)`;
  const exp2 = '413 once over the limit, or 408 / connection closed within the request timeout';
  if (!(await alive())) fail(g, name, 'critical', v.s ?? v.code, exp2, 'the app stopped answering');
  else if (v.kind === 'silent') fail(g, name, 'high', 'no answer', exp2, `still reading after ${(v.sent / 2 ** 20).toFixed(1)} MB and ${HANG_MS} ms: no body limit, no timeout`);
  else if (v.kind === 'status' && !is4xx(v.s)) fail(g, name, 'high', v.s, exp2);
  else pass(g, name, v.s ?? 'closed', exp2);
};

// Raw requests node:http refuses to send. Node, uvicorn, Go and most frameworks answer these from the parser, before any
// middleware: the app's common headers (request id, CORS, cache, security headers) are missing unless the parser error is handled.
const raw = (payload) => new Promise((done) => {
  const socket = connect({ host: base.hostname, port: Number(base.port || 80) });
  let data = Buffer.alloc(0), over = false;
  const parse = (t) => {
    const lines = t.split('\r\n');
    const s = Number(lines[0].match(/^HTTP\/\d(?:\.\d)? (\d{3})/)?.[1]);
    const headers = Object.fromEntries(lines.slice(1).filter((l) => l.includes(':')).map((l) => [l.slice(0, l.indexOf(':')).trim().toLowerCase(), l.slice(l.indexOf(':') + 1).trim()]));
    return Number.isInteger(s) ? { kind: 'status', s, headers } : { kind: 'garbled', text: lines[0].slice(0, 40) };
  };
  const finish = (v) => { if (over) return; over = true; clearTimeout(timer); socket.destroy(); done(v); };
  const timer = setTimeout(() => finish({ kind: 'silent' }), 3000);
  socket.on('connect', () => socket.write(payload));
  socket.on('data', (d) => { data = Buffer.concat([data, d]); const i = data.indexOf('\r\n\r\n'); if (i >= 0) finish(parse(data.subarray(0, i).toString('latin1'))); });
  socket.on('error', (e) => finish(data.length ? parse(data.toString('latin1')) : { kind: 'closed', code: e.code }));
  socket.on('close', () => finish(data.length ? parse(data.toString('latin1')) : { kind: 'closed' }));
});
const parserErrors = async () => {
  const g = 'parser';
  const host = base.host;
  const RAW = [
    ['GARBAGE request line', 'GARBAGE\r\n\r\n', '400'],
    ['non-ASCII bytes in the request path', Buffer.from(`GET /ñandú HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`, 'utf8'), '400 or 404'],
    ['20 KB header', `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\nX-Big: ${'a'.repeat(20 << 10)}\r\n\r\n`, '431'],
    ['conflicting Content-Length and Transfer-Encoding', `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n`, '400 (request smuggling guard)'],
  ];
  for (const [what, payload, want] of RAW) {
    const v = await raw(payload);
    const up = await alive();
    const name = `raw: ${what}`;
    const expected = `${want} with the common headers, then the connection closes`;
    if (!up) { fail(g, name, 'critical', v.s ?? v.kind, expected, 'the app stopped answering'); continue; }
    if (v.kind === 'closed') { pass(g, name, 'closed', expected); continue; }
    if (v.kind !== 'status') { fail(g, name, 'high', v.kind, expected, v.text ?? 'no answer and no close in 3 s'); continue; }
    const missing = opt.common.filter((h) => v.headers[h] === undefined);
    if (!is4xx(v.s)) fail(g, name, 'high', v.s, expected);
    else if (missing.length && !opt.rawExempt) fail(g, name, 'medium', v.s, expected, `the parser's answer lacks ${missing.join(', ')}: the error is answered before the app's middleware`);
    else row({ group: g, name, verdict: 'pass', got: v.s, expected, evidence: missing.length ? `common headers exempt: ${opt.rawExempt}` : undefined });
  }
};

// Path and query edge cases on every known route.
const paths = async () => {
  const g = 'paths';
  const routes = [...new Set(['/', ...opt.writes.map((w) => w.path), ...opt.reads])];
  const check = async (name, path, expected) => {
    const r = await send('GET', path);
    if (r.s === null) fail(g, name, 'critical', r.err, expected, (await alive()) ? 'connection dropped' : 'the app stopped answering');
    else if (r.s >= 500) fail(g, name, 'high', r.s, expected);
    else pass(g, name, r.s, expected);
  };
  for (const r of routes) {
    const [p, q] = r.split('?');
    await check(`GET /${p} (double slash)`, '/' + p, 'a 4xx or the same resource, never a 5xx: "//x" is a path, not a host');
    await check(`GET ${p.replace(/\/$/, '')}/% (broken percent-encoding in the path)`, `${p.replace(/\/$/, '')}/%`, '400 or 404, never a 5xx');
    await check(`GET ${p}?pct=%FF% (broken percent-encoding in the query)`, `${p}?${q ? `${q}&` : ''}pct=%FF%`, '400, never a 5xx');
    for (const [k] of [...new URLSearchParams(q ?? '')].filter(([, v]) => /^-?\d+$/.test(v)))
      for (const huge of ['9'.repeat(30), '-' + '9'.repeat(30), '1e3', '']) {
        const sp = new URLSearchParams(q); sp.set(k, huge);
        await check(`GET ${p}?${k}=${huge.slice(0, 6) || '(empty)'} (number the parser cannot hold)`, `${p}?${sp}`, '400 or a clamped 2xx, never a 5xx');
      }
  }
  for (const r of [...new Set([...opt.writes.map((w) => w.path), ...opt.reads.map((x) => x.split('?')[0])])]) for (const m of ['HEAD', 'OPTIONS']) {
    const res = await send(m, r);
    const name = `${m} ${r}`;
    if (res.s === null || res.s >= 500) fail(g, name, 'high', res.s ?? res.err, '2xx, or 405 with Allow');
    else if (res.s === 405 && !res.headers.allow) fail(g, name, 'low', 405, '405 must name the allowed methods in Allow (RFC 9110 15.5.6)');
    else pass(g, name, res.s, '2xx, or 405 with Allow');
  }
  const LEAKS = [['/.git/config', /\[core\]/], ['/.env', /^[A-Z][A-Z0-9_]*=/m], ['/package.json', /"(dependencies|scripts)"\s*:/], ['/../../etc/passwd', /root:.*:0:0:/], ['/%2e%2e/%2e%2e/etc/passwd', /root:.*:0:0:/]];
  for (const [p, marker] of LEAKS) {
    const r = await send('GET', p, { common: false });
    const leaked = is2xx(r.s) && !/^\s*<(!doctype|html)/i.test(r.text) && marker.test(r.text);
    if (leaked) fail(g, `GET ${p} (file the app must not serve)`, 'critical', r.s, '404', 'the file content came back');
    else pass(g, `GET ${p} (file the app must not serve)`, r.s ?? r.err, '404 (an SPA index page is fine)');
  }
};

// Free text taken literally: % and _ are LIKE wildcards; a quote that breaks the SQL is an injection.
const search = async ({ path: r, param }) => {
  const g = 'search';
  const [p, q] = r.split('?');
  const at = (v) => { const sp = new URLSearchParams(q ?? ''); if (v === null) sp.delete(param); else sp.set(param, v); const s = sp.toString(); return s ? `${p}?${s}` : p; };
  const all = await send('GET', at(null));
  const listsRows = is2xx(all.s) && all.text.length > 2;
  if (!listsRows) notRun(g, `${p} ?${param}= wildcard rows`, `the unfiltered list is empty or failed (${all.s ?? all.err}): create a row first, or the wildcard check proves nothing`);
  for (const v of ['%', '_', "'", '"', '\\', "' OR 1=1 --", "%' OR '1'='1"]) {
    const res = await send('GET', at(v));
    const name = `GET ${at(v)}`;
    const expected = '200 with only the rows that contain that literal text (usually none)';
    if (res.s === null || res.s >= 500) { fail(g, name, /'/.test(v) ? 'critical' : 'high', res.s ?? res.err, expected, /'/.test(v) ? 'a quote breaks the query: SQL is built by string concatenation' : undefined); continue; }
    if (listsRows && is2xx(res.s) && (v === '%' || v === '_') && res.text === all.text) { fail(g, name, 'high', res.s, expected, `${v} matched every row: it reached LIKE unescaped`); continue; }
    if (listsRows && is2xx(res.s) && v.includes('OR') && res.text.length >= all.text.length) { fail(g, name, 'critical', res.s, expected, 'the injected OR matched at least every row of the unfiltered list'); continue; }
    pass(g, name, res.s, expected);
  }
};

// Identical creates at once: check-then-insert lets more than one through, or turns the constraint violation into a 500.
// Last-byte synchronization over raw sockets: every connection gets its request minus the final byte, then the final bytes go
// out in one synchronous loop. Three details keep the racers inside one server read batch:
// - Nagle is off: a 1-byte write behind unacknowledged data otherwise waits for the peer's delayed ACK (~200 ms on Windows).
// - A pacer request (same endpoint, different key) is released a few ms first. An event loop wakes on the first byte that
//   arrives and handles that request alone; if the handler then blocks the loop (a synchronous fsync takes ~100 ms on
//   Windows), its timers fire before the next read, and requests that arrived a microsecond apart are served one by one.
//   The pacer takes that first wake-up, and the racers arrive while the loop is busy with it.
// - Every dropped connection is reported with its error code (ECONNRESET, EMPTY_RESPONSE, TIMEOUT...).
const RACERS = 8;
const PACER_LEAD_MS = 5;
const race = async (u) => {
  const g = 'concurrency';
  const name = `${u.method} ${u.path} ×${RACERS} identical requests at once`;
  const expected = 'exactly one 201, the other seven 409';
  const bytesOf = (p) => {
    const data = Buffer.from(p.text);
    const head = Object.entries({ host: base.host, ...opt.extra, 'content-type': p.type, 'content-length': data.length, connection: 'close' })
      .map(([k, v]) => `${k}: ${v}`).join('\r\n');
    return Buffer.concat([Buffer.from(`${u.method} ${u.path} HTTP/1.1\r\n${head}\r\n\r\n`), data]);
  };
  const open = (bytes) => new Promise((ready) => {
    const sock = connect({ host: base.hostname.replace(/^\[|\]$/g, ''), port: Number(base.port || 80), noDelay: true });
    const chunks = [];
    let err = null, settle;
    const settled = new Promise((r) => { settle = r; });
    sock.setTimeout(10_000, () => { err ??= 'TIMEOUT'; sock.destroy(); });
    sock.on('data', (d) => chunks.push(d));
    sock.on('error', (e) => { err ??= e.code ?? e.message; ready({ sock: null, settled }); });
    sock.on('close', () => {
      const text = Buffer.concat(chunks).toString('latin1');
      const m = text.match(/^HTTP\/1\.[01] (\d{3})/);
      if (!m) return settle({ s: null, err: err ?? (text ? 'BAD_RESPONSE' : 'EMPTY_RESPONSE') });
      const headers = Object.fromEntries(text.split('\r\n\r\n')[0].split('\r\n').slice(1)
        .map((l) => [l.slice(0, l.indexOf(':')).trim().toLowerCase(), l.slice(l.indexOf(':') + 1).trim()]));
      checkCommon(`${u.method} ${u.path} → ${m[1]}`, headers);
      settle({ s: Number(m[1]) });
    });
    sock.on('connect', () => sock.write(bytes.subarray(0, -1), () => ready({ sock, settled, last: bytes.subarray(-1) })));
  });
  const racerBytes = bytesOf(wire(u.body));
  const [pacer, ...racers] = await Promise.all([open(bytesOf(wire(u.body))), ...Array.from({ length: RACERS }, () => open(racerBytes))]);
  await new Promise((r) => setTimeout(r, 50));
  if (pacer.sock && !pacer.sock.destroyed) pacer.sock.write(pacer.last);
  await new Promise((r) => setTimeout(r, PACER_LEAD_MS));
  for (const c of racers) if (c.sock && !c.sock.destroyed) c.sock.write(c.last);
  const [, ...all] = await Promise.all([pacer.settled, ...racers.map((c) => c.settled)]);
  const codes = all.map((x) => x.s ?? `drop:${x.err}`);
  const ok = codes.filter((s) => typeof s === 'number' && s < 400).length;
  const five = codes.filter((s) => typeof s === 'number' && s >= 500).length;
  const drop = codes.filter((s) => typeof s !== 'number').length;
  if (drop === RACERS) notRun(g, name, `no response at all (${codes.join(' ')})`);
  else if (ok === 0 && !five && !drop) notRun(g, name, `none succeeded (${codes.join(' ')}): the legitimate body is refused, so the race was not tried`);
  else if (ok > 1) fail(g, name, 'critical', codes.join(' '), expected, `${ok} succeeded: duplicates stored; the unique key is not enforced by the database`);
  else if (five || drop) fail(g, name, 'high', codes.join(' '), expected, 'the constraint violation escapes as a 5xx or a dropped connection: map the unique-violation error to 409');
  else if (codes.some((s) => s !== 409 && typeof s === 'number' && s >= 400)) row({ group: g, name, verdict: 'pass', got: codes.join(' '), expected, evidence: 'refusals are 4xx but not 409; fine if the contract says so' });
  else pass(g, name, codes.join(' '), expected);
};

// The database fails while a legitimate write arrives: one 5xx with the generic error body, and the process stays up.
const fault = async () => {
  const g = 'faults';
  const w = opt.writes[0];
  const name = `${w?.method ?? 'write'} ${w?.path ?? ''} with the SQLite file locked (BEGIN EXCLUSIVE)`;
  const expected = '503 or 500 with the generic error body and the common headers; the process keeps answering';
  let sqlite; try { sqlite = await import('node:sqlite'); } catch { return notRun(g, name, 'node:sqlite is not available (Node 22.5+)'); }
  if (!w) return notRun(g, name, '--fault-sqlite needs a --write');
  const faultPath = resolveFsPath(opt.fault);
  if (!existsSync(faultPath)) return notRun(g, name, `looked for the database at "${faultPath}" (from "${opt.fault}") and it does not exist: pass the server the same absolute Windows path`);
  const db = new sqlite.DatabaseSync(faultPath, { timeout: 3000 });
  let res;
  try { db.exec('BEGIN EXCLUSIVE'); const p = wire(w.body); res = await send(w.method, w.path, { body: p.text, type: p.type }); }
  catch (e) { return notRun(g, name, `could not lock the database: ${e.message}`); }
  finally { try { db.exec('ROLLBACK'); } catch { /* not locked */ } db.close(); }
  await new Promise((r) => setTimeout(r, 300));
  const up = await alive();
  if (!up) fail(g, name, 'critical', res.s ?? res.err, expected, 'the process died: an error from the database escaped a handler (unhandled rejection / uncaught exception)');
  else if (res.s === null) fail(g, name, 'high', res.err, expected, 'the connection was dropped instead of an error response');
  else if (res.s < 500) fail(g, name, 'high', res.s, expected, 'a failed write was reported as something else');
  else if (/at \S+ \(|node:internal|Traceback|SQLITE_|sqlite3\./i.test(res.text)) fail(g, name, 'medium', res.s, expected, 'the 5xx body leaks internals (stack, driver error)');
  else pass(g, name, res.s, expected);
};

// Authentication and object ownership on the item the legitimate write created.
const access = async () => {
  const g = 'auth';
  const hasCreds = Object.keys(opt.extra).some((k) => ['authorization', 'cookie', 'x-api-key'].includes(k));
  for (const w of opt.writes) {
    const p = wire(w.body);
    const legit = await send(w.method, w.path, { body: p.text, type: p.type });
    if (legit.s === null || legit.s >= 400) { fail(g, `${w.method} ${w.path} legitimate request`, legit.s >= 500 ? 'high' : 'medium', legit.s ?? legit.err, '2xx', 'the legitimate request failed: every other row of this write is unreliable'); continue; }
    pass(g, `${w.method} ${w.path} legitimate request`, legit.s, '2xx');
    const item = itemUrlOf(legit);
    if (hasCreds) {
      const q = wire(w.body);
      const r = await send(w.method, w.path, { body: q.text, type: q.type, auth: 'none' });
      if (r.s !== null && r.s < 400) fail(g, `${w.method} ${w.path} without credentials`, 'critical', r.s, '401');
      else pass(g, `${w.method} ${w.path} without credentials`, r.s ?? r.err, '401');
      if (item) {
        const r2 = await send('GET', item, { auth: 'none' });
        if (is2xx(r2.s)) fail(g, `GET ${item} without credentials`, 'critical', r2.s, '401'); else pass(g, `GET ${item} without credentials`, r2.s ?? r2.err, '401');
      }
    }
    if (Object.keys(opt.other).length) {
      if (!item) { notRun(g, `${w.method} ${w.path} ownership`, 'the create answered no Location and --item-path was not given'); continue; }
      for (const m of ['GET', 'DELETE']) {
        const r = await send(m, item, { auth: 'b' });
        const name = `${m} ${item} as another user (IDOR / BOLA)`;
        if (r.s !== null && r.s < 300) fail(g, name, 'critical', r.s, '404 (or 403)', "another user's credentials reach this object");
        else pass(g, name, r.s ?? r.err, '404 (or 403)');
      }
    }
  }
  for (const r of opt.reads) if (hasCreds) {
    const res = await send('GET', r, { auth: 'none' });
    if (is2xx(res.s)) fail(g, `GET ${r} without credentials`, 'critical', res.s, '401'); else pass(g, `GET ${r} without credentials`, res.s ?? res.err, '401');
  }
};

// Cookie-authenticated apps: a write from another origin must be refused (CSRF). "Same site" includes another port.
const csrf = async () => {
  const g = 'csrf';
  const origins = [['from another site', { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' }],
    ['from another port of the same host', { origin: `http://${base.hostname}:${Number(base.port || 80) + 1}`, 'sec-fetch-site': 'same-site' }],
    ['with Origin: null', { origin: 'null' }]];
  for (const w of opt.writes) for (const [label, headers] of origins) {
    const p = wire(w.body);
    const r = await send(w.method, w.path, { body: p.text, type: p.type, headers });
    const name = `${w.method} ${w.path} ${label}`;
    if (r.s !== null && r.s < 400) fail(g, name, 'critical', r.s, '403: the Origin is not this app');
    else if (r.s === 409 || r.s === 422) notRun(g, name, `answered ${r.s}: the body was refused before the origin check`);
    else pass(g, name, r.s ?? r.err, '403');
  }
};

// ---------- run ----------
const first = await send('GET', '/', { common: false });
if (first.s === null) { console.error(`The app does not answer at ${base.origin}: ${first.err}`); process.exit(2); }

if (opt.persistSave || opt.persistVerify) {
  const file = opt.persistSave ?? opt.persistVerify;
  if (opt.persistSave) {
    const w = opt.writes[0];
    if (!w) usage('--persist-save needs a --write.');
    const p = wire(w.body);
    const r = await send(w.method, w.path, { body: p.text, type: p.type, common: false });
    const item = itemUrlOf(r);
    if (!item) { console.error(`The create answered ${r.s} without a readable location (give --item-path).`); process.exit(2); }
    const read = await send('GET', item, { common: false });
    writeFileSync(file, JSON.stringify({ item, status: read.s, body: read.text }, null, 2));
    console.log(`saved ${item} (${read.s}) to ${file}. Restart the app, then run --persist-verify ${file}.`);
    process.exit(is2xx(read.s) ? 0 : 1);
  }
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  const now = await send('GET', saved.item, { common: false });
  const same = now.s === saved.status && now.text === saved.body;
  console.log(`${same ? 'PASS' : 'FAIL critical'}  GET ${saved.item} after restart: ${now.s} (before: ${saved.status})${same ? '' : ' — expected the same status and body: the data is not durable'}`);
  process.exit(same ? 0 : 1);
}

await access();
for (const w of opt.writes) await malformedInput(w);
await paths();
for (const s of opt.searches) await search(s);
await parserErrors();
for (const w of opt.writes) await resources(w);
for (const u of opt.uniques) await race(u);
if (opt.csrf) await csrf();
if (opt.fault) await fault();
if (pending.length) row({ group: 'headers', name: 'responses outside any row', verdict: 'fail', severity: 'medium', expected: `every response carries ${opt.common.join(', ')}`, evidence: '' });

const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const failed = rows.filter((r) => r.verdict === 'fail').sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
const skipped = rows.filter((r) => r.verdict === 'not-run');
if (opt.json) console.log(JSON.stringify({ base: base.origin, rows }, null, 2));
else {
  for (const r of rows) {
    const mark = r.verdict === 'fail' ? `FAIL ${r.severity.padEnd(8)}` : r.verdict === 'not-run' ? 'NOT RUN      ' : 'pass         ';
    console.log(`${mark} ${String(r.got ?? '-').padEnd(5)} [${r.group}] ${r.name}`);
    if (r.verdict !== 'pass') console.log(`${' '.repeat(20)}expected: ${r.expected || '-'}${r.evidence ? `\n${' '.repeat(20)}evidence: ${r.evidence}` : ''}`);
  }
  const by = (s) => failed.filter((r) => r.severity === s).length;
  console.log(`\n${rows.length} probes · ${failed.length} findings (critical ${by('critical')}, high ${by('high')}, medium ${by('medium')}, low ${by('low')}) · ${skipped.length} not run`);
}
process.exit(failed.length ? 1 : skipped.length ? 2 : 0);
