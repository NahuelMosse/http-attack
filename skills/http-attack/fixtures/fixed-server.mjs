// The same API as vulnerable-server.mjs, with each defect fixed. http-attack must report nothing.
// node fixed-server.mjs <port | 0> <sqlite-file | :memory:>   Users: "Authorization: Bearer alice" / "Bearer bob", or "Cookie: session=alice" / "session=bob".
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const [port, file] = process.argv.slice(2);
const db = new DatabaseSync(file);
db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL');
db.exec('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, owner TEXT, name TEXT, email TEXT UNIQUE); CREATE TABLE IF NOT EXISTS audit (at TEXT); CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT UNIQUE)');

const BODY_LIMIT = 64 * 1024;
const MAX_PAGE = 100;
const common = () => ({ 'x-request-id': randomUUID(), 'cache-control': 'no-store' });
const reply = (res, status, body, extra = {}) => {
  if (res.headersSent) return;
  res.writeHead(status, { 'content-type': 'application/json', ...common(), ...extra });
  res.end(body === undefined ? '' : JSON.stringify(body));
};
class HttpError extends Error { constructor(status, body, extra) { super(body.error); Object.assign(this, { status, body, extra }); } }
// Bearer tokens or a session cookie (session=alice / session=bob): the cookie is what the CSRF probes attack.
const userOf = (req) => ({ 'Bearer alice': 'alice', 'Bearer bob': 'bob' })[req.headers.authorization] ?? ({ 'session=alice': 'alice', 'session=bob': 'bob' })[req.headers.cookie];

// The media type is checked before reading; bytes are counted while reading; decoding is strict.
const readJson = (req) => new Promise((done, fail) => {
  const type = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return fail(new HttpError(415, { error: 'unsupported media type' }));
  const parts = []; let size = 0, over = false;
  req.on('data', (d) => {
    if (over) return;
    size += d.length;
    if (size > BODY_LIMIT) { over = true; fail(new HttpError(413, { error: 'too large' }, { connection: 'close' })); return; }
    parts.push(d);
  });
  req.on('end', () => {
    if (over) return;
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts)); } catch { return fail(new HttpError(400, { error: 'invalid utf-8' })); }
    try { done(JSON.parse(text)); } catch { fail(new HttpError(400, { error: 'invalid json' })); }
  });
  req.on('error', fail);
});
const escapeLike = (s) => s.replace(/[\\%_]/g, (c) => '\\' + c);
const dbError = (e) => {
  if (/UNIQUE constraint failed/.test(e.message)) return new HttpError(409, { error: 'exists' });
  if (/database is locked|SQLITE_BUSY/i.test(e.message)) return new HttpError(503, { error: 'unavailable' }, { 'retry-after': '1' });
  return e;
};

const handle = async (req, res) => {
  const [rawPath, rawQuery = ''] = req.url.split(/\?(.*)/s);
  let path;
  try { path = decodeURIComponent(rawPath); } catch { throw new HttpError(400, { error: 'bad path' }); }
  const query = new URLSearchParams(rawQuery);
  if (path === '/') return reply(res, 200, { ok: true });
  const m = path.match(/^\/(items|notes)(?:\/([1-9][0-9]{0,15}))?$/);
  if (!m) throw new HttpError(404, { error: 'not found' });
  const [, table, id] = m;
  const allow = table === 'notes' ? (id ? 'GET' : 'POST') : (id ? 'GET, HEAD, DELETE' : 'GET, HEAD, POST');
  if (req.method === 'OPTIONS') return reply(res, 204, undefined, { allow: `${allow}, OPTIONS` });
  if (!allow.split(', ').includes(req.method)) throw new HttpError(405, { error: 'method not allowed' }, { allow });
  // A write from another origin is refused before anything else looks at it (CSRF).
  if (req.headers.origin !== undefined && req.headers.origin !== `http://${req.headers.host}`) throw new HttpError(403, { error: 'forbidden origin' });
  const who = userOf(req);
  if (!who) throw new HttpError(401, { error: 'unauthorized' }, { 'www-authenticate': 'Bearer' });
  if (id) {
    const item = db.prepare(`SELECT * FROM ${table} WHERE id = ? AND owner = ?`).get(Number(id), who);
    if (!item) throw new HttpError(404, { error: 'not found' });
    if (req.method !== 'DELETE') return reply(res, 200, table === 'notes' ? { id: item.id, title: item.title } : { id: item.id, name: item.name, email: item.email });
    db.prepare('DELETE FROM items WHERE id = ? AND owner = ?').run(item.id, who);
    return reply(res, 204);
  }
  if (req.method === 'GET') {
    const limit = query.get('limit') ?? '50';
    if (query.getAll('limit').length > 1 || !/^[0-9]+$/.test(limit) || Number(limit) > MAX_PAGE) throw new HttpError(400, { error: 'invalid limit' });
    const q = query.get('q') ?? '';
    const rows = db.prepare("SELECT id, name, email FROM items WHERE owner = ? AND name LIKE ? ESCAPE '\\' ORDER BY id LIMIT ?").all(who, `%${escapeLike(q)}%`, Number(limit));
    return reply(res, 200, rows);
  }
  const b = await readJson(req);
  try {
    db.prepare('INSERT INTO audit VALUES (?)').run(new Date().toISOString());
    if (table === 'notes') {
      if (!b || typeof b !== 'object' || typeof b.title !== 'string' || !b.title.trim()) throw new HttpError(400, { error: 'invalid' });
      const { lastInsertRowid } = db.prepare('INSERT INTO notes (owner, title) VALUES (?, ?)').run(who, b.title.trim());
      return reply(res, 201, { id: Number(lastInsertRowid), title: b.title.trim() }, { location: `/notes/${Number(lastInsertRowid)}` });
    }
    if (!b || typeof b !== 'object' || typeof b.name !== 'string' || typeof b.email !== 'string' || !b.name.trim()) throw new HttpError(400, { error: 'invalid' });
    const { lastInsertRowid } = db.prepare('INSERT INTO items (owner, name, email) VALUES (?, ?, ?)').run(who, b.name.trim(), b.email);
    const newId = Number(lastInsertRowid);
    return reply(res, 201, { id: newId, name: b.name.trim(), email: b.email }, { location: `/items/${newId}` });
  } catch (e) { throw e instanceof HttpError ? e : dbError(e); }
};

const server = createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (e instanceof HttpError) {
      reply(res, e.status, e.body, e.extra);
      if (e.status === 413) res.on('finish', () => req.destroy());
      return;
    }
    console.error(e);
    reply(res, 500, { error: 'internal' });
  });
});
// Malformed requests are answered by the parser, before the handler: they get the common headers here.
server.on('clientError', (err, socket) => {
  if (!socket.writable) return socket.destroy();
  const status = err.code === 'HPE_HEADER_OVERFLOW' ? 431 : err.code === 'ERR_HTTP_REQUEST_TIMEOUT' ? 408 : 400;
  const body = JSON.stringify({ error: 'bad request' });
  const head = { 'content-type': 'application/json', ...common(), connection: 'close', 'content-length': Buffer.byteLength(body) };
  socket.end(`HTTP/1.1 ${status} ${status === 431 ? 'Request Header Fields Too Large' : status === 408 ? 'Request Timeout' : 'Bad Request'}\r\n${Object.entries(head).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${body}`);
});
server.requestTimeout = 10_000;
server.headersTimeout = 5_000;
server.listen(Number(port), '127.0.0.1', () => console.log(`fixed on ${server.address().port}`));
