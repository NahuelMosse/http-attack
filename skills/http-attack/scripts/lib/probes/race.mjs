import { connect } from 'node:net';
import { wire } from '../body.mjs';

// Identical creates at once: check-then-insert lets more than one through, or turns the constraint violation into a 500.
// Last-byte synchronization over raw sockets: every connection gets its request minus the final byte, then the final bytes go
// out in one synchronous loop. Three details keep the racers inside one server read batch:
// - Nagle is off: a 1-byte write behind unacknowledged data otherwise waits for the peer's delayed ACK (~200 ms on Windows).
// - A pacer request (same endpoint, different key) is released a few ms first. An event loop wakes on the first byte that
//   arrives and handles that request alone; if the handler then blocks the loop (a synchronous fsync takes ~100 ms on
//   Windows), its timers fire before the next read, and requests that arrived a microsecond apart are served one by one.
//   The pacer takes that first wake-up, and the racers arrive while the loop is busy with it.
// - Every dropped connection is reported with its error code (ECONNRESET, EMPTY_RESPONSE, TIMEOUT...).
const PACER_LEAD_MS = 5;
const SETTLE_MS = 50;
const SOCKET_TIMEOUT_MS = 10_000;

const decodeChunked = (text) => {
  let out = '', rest = text;
  for (;;) {
    const nl = rest.indexOf('\r\n');
    const size = parseInt(rest.slice(0, nl), 16);
    if (nl < 0 || !Number.isInteger(size) || size === 0) return out;
    out += rest.slice(nl + 2, nl + 2 + size);
    rest = rest.slice(nl + 2 + size + 2);
  }
};

const parseResponse = (text) => {
  const m = text.match(/^HTTP\/1\.[01] (\d{3})/);
  if (!m) return null;
  const [head, ...bodyParts] = text.split('\r\n\r\n');
  const headers = Object.fromEntries(head.split('\r\n').slice(1).filter((l) => l.includes(':'))
    .map((l) => [l.slice(0, l.indexOf(':')).trim().toLowerCase(), l.slice(l.indexOf(':') + 1).trim()]));
  const body = bodyParts.join('\r\n\r\n');
  return { s: Number(m[1]), headers, text: headers['transfer-encoding'] === 'chunked' ? decodeChunked(body) : body };
};

// The identity of the item a success created: its Location, else the id in the JSON body.
const identityOf = (r) => {
  if (r.headers.location) return r.headers.location;
  try { const j = JSON.parse(r.text); const id = j?.id ?? j?.data?.id ?? j?.item?.id; return id === undefined ? null : `id:${id}`; } catch { return null; }
};

export async function raceProbe(run, u) {
  const { client, opts } = run;
  const target = `${u.method} ${u.path}`;
  const spec = { group: 'concurrency', probe: 'race-identical-creates', target, name: `${target} x${opts.raceCount} identical requests at once` };
  const st = run.settings(u.method, u.path);
  const expected = `exactly one 201, the other ${opts.raceCount - 1} 409`;
  const bytesOf = (p) => {
    const data = Buffer.from(p.text);
    const head = Object.entries({ host: client.base.host, ...opts.headers, 'content-type': p.type, 'content-length': data.length, connection: 'close' })
      .map(([k, v]) => `${k}: ${v}`).join('\r\n');
    return Buffer.concat([Buffer.from(`${u.method} ${u.path} HTTP/1.1\r\n${head}\r\n\r\n`), data]);
  };
  const open = (bytes) => new Promise((ready) => {
    const sock = connect({ host: client.host, port: client.port, noDelay: true });
    const chunks = [];
    let err = null, settle;
    const settled = new Promise((r) => { settle = r; });
    sock.setTimeout(SOCKET_TIMEOUT_MS, () => { err ??= 'TIMEOUT'; sock.destroy(); });
    sock.on('data', (d) => chunks.push(d));
    sock.on('error', (e) => { err ??= e.code ?? e.message; ready({ sock: null, settled }); });
    sock.on('close', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const parsed = parseResponse(text);
      if (!parsed) return settle({ s: null, err: err ?? (text ? 'BAD_RESPONSE' : 'EMPTY_RESPONSE') });
      client.noteHeaders(`${u.method} ${u.path} -> ${parsed.s}`, parsed.headers);
      settle(parsed);
    });
    sock.on('connect', () => sock.write(bytes.subarray(0, -1), () => ready({ sock, settled, last: bytes.subarray(-1) })));
  });

  let last = null;
  for (let attempt = 1; attempt <= opts.raceAttempts; attempt++) {
    const racerBytes = bytesOf(wire(u, st));
    const [pacer, ...racers] = await Promise.all([open(bytesOf(wire(u, st))), ...Array.from({ length: opts.raceCount }, () => open(racerBytes))]);
    await new Promise((r) => setTimeout(r, SETTLE_MS));
    if (pacer.sock && !pacer.sock.destroyed) pacer.sock.write(pacer.last);
    await new Promise((r) => setTimeout(r, PACER_LEAD_MS));
    for (const c of racers) if (c.sock && !c.sock.destroyed) c.sock.write(c.last);
    const [, ...all] = await Promise.all([pacer.settled, ...racers.map((c) => c.settled)]);
    const verdict = judge(all);
    last = { ...verdict, attempt };
    if (verdict.kind !== 'pass') break;
  }

  function judge(all) {
    const codes = all.map((x) => x.s ?? `drop:${x.err}`);
    const created = all.filter((x) => x.s >= 200 && x.s < 300);
    const five = all.filter((x) => x.s >= 500).length;
    const drop = all.filter((x) => x.s === null).length;
    const joined = codes.join(' ');
    if (drop === all.length) return { kind: 'not-run', codes: joined, why: `no response at all (${joined})` };
    if (!created.length && !five && !drop) return { kind: 'not-run', codes: joined, why: `none succeeded (${joined}): the legitimate body is refused, so the race was not tried` };
    if (created.length > 1 && !st.idempotentCreate) {
      const ids = created.map(identityOf);
      const distinct = new Set(ids.filter(Boolean));
      if (ids.some((x) => x === null) || distinct.size > 1) {
        return { kind: 'duplicates', codes: joined, why: `${created.length} succeeded${distinct.size > 1 ? ` with ${distinct.size} distinct items` : ''}: duplicates stored; the unique key is not enforced by the database (a create that is idempotent by design: idempotentCreate in the config)` };
      }
      return { kind: 'pass', codes: joined, why: 'several successes returned the same item: the create is idempotent' };
    }
    if (five) return { kind: 'five', codes: joined, why: 'the constraint violation escapes as a 5xx: map the unique-violation error to 409', sample: all.find((x) => x.s >= 500) };
    if (drop) return { kind: 'drop', codes: joined, why: 'the constraint violation closes the connection: map the unique-violation error to 409' };
    if (codes.some((s) => s !== 409 && s >= 400)) return { kind: 'pass', codes: joined, why: 'refusals are 4xx but not 409; fine if the contract says so' };
    return { kind: 'pass', codes: joined };
  }

  const at = last.attempt > 1 || opts.raceAttempts > 1 ? ` (attempt ${last.attempt} of ${opts.raceAttempts})` : '';
  if (last.kind === 'not-run') run.notRun(spec, last.why);
  else if (last.kind === 'duplicates') run.fail('duplicates-stored', spec, last.codes, expected, last.why + at);
  else if (last.kind === 'five') await run.transportFault(last.sample, { ...spec, hint: last.why }, expected);
  else if (last.kind === 'drop') run.fail('connection-dropped', spec, last.codes, expected, last.why + at);
  else run.pass(spec, last.codes, expected, last.why);
}
