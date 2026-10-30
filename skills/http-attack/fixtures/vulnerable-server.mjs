// A deliberately broken API, to prove that http-attack finds what it claims to find.
// node vulnerable-server.mjs <port | 0> <sqlite-file | :memory:>   Users: "Authorization: Bearer alice" and "Bearer bob".
// Every defect below is one the script must report. Do not copy this code.
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const [port, file] = process.argv.slice(2);
const db = new DatabaseSync(file);
db.exec('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, owner TEXT, name TEXT, email TEXT UNIQUE); CREATE TABLE IF NOT EXISTS audit (at TEXT); '
  + 'CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT)');

const reply = (res, status, body, extra = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', 'x-request-id': randomUUID(), 'cache-control': 'no-store', ...extra });
  res.end(body === undefined ? '' : JSON.stringify(body));
};
const userOf = (req) => ({ 'Bearer alice': 'alice', 'Bearer bob': 'bob' })[req.headers.authorization];
const readAll = (req) => new Promise((done) => { const parts = []; req.on('data', (d) => parts.push(d)); req.on('end', () => done(Buffer.concat(parts).toString())); });

// No 'clientError' handler: Node's parser answers malformed requests without the common headers.
createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://local'); // "//" throws; "//items" becomes host "items"
    const path = decodeURIComponent(url.pathname); // "%" throws
    if (path === '/') return reply(res, 200, { ok: true });
    if (path === '/.git/config') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('[core]\n\trepositoryformatversion = 0\n'); } // the repo is served
    if (path === '/notes' && req.method === 'POST') { // no authentication, no unique key, no CSRF check, no body limit
      const raw = await readAll(req);
      let b; try { b = JSON.parse(raw); } catch { return reply(res, 400, { error: 'bad json' }); }
      if (typeof b?.title !== 'string') return reply(res, 400, { error: 'invalid' });
      await new Promise((r) => setTimeout(r, 20));
      const { lastInsertRowid } = db.prepare('INSERT INTO notes (title) VALUES (?)').run(b.title);
      return reply(res, 201, { id: Number(lastInsertRowid), title: b.title }, { location: `/notes/${Number(lastInsertRowid)}` });
    }
    const note = path.match(/^\/notes\/(\d+)$/);
    if (note) {
      const row = db.prepare('SELECT id, title FROM notes WHERE id = ?').get(Number(note[1]));
      return row ? reply(res, 200, row) : reply(res, 404, { error: 'not found' });
    }
    const who = userOf(req);
    if (path === '/items') {
      if (!who) return reply(res, 401, { error: 'unauthorized' });
      if (req.method === 'GET') {
        const q = url.searchParams.get('q') ?? '';
        const limit = url.searchParams.get('limit') ?? '50';
        // String-built SQL: LIKE wildcards pass through, a quote breaks it, a huge limit is a SQL error.
        const rows = db.prepare(`SELECT id, name, email FROM items WHERE owner = '${who}' AND name LIKE '%${q}%' ORDER BY id LIMIT ${Number(limit)}`).all();
        return reply(res, 200, rows);
      }
      if (req.method === 'POST') {
        const raw = await readAll(req); // the whole body is read before the content type is looked at
        if (req.headers['content-type'].split(';')[0] !== 'application/json') return reply(res, 415, { error: 'json only' }); // crashes without the header; case-sensitive
        let b; try { b = JSON.parse(raw); } catch { return reply(res, 400, { error: 'bad json' }); }
        if (!b.name || typeof b.email !== 'string') return reply(res, 400, { error: 'invalid' });
        if (db.prepare('SELECT 1 FROM items WHERE email = ?').get(b.email)) return reply(res, 409, { error: 'exists' });
        await new Promise((r) => setTimeout(r, 20)); // check, then insert: a race window
        const { lastInsertRowid } = db.prepare('INSERT INTO items (owner, name, email) VALUES (?, ?, ?)').run(who, String(b.name), b.email);
        const id = Number(lastInsertRowid);
        return reply(res, 201, { id, name: String(b.name), email: b.email }, { location: `/items/${id}` });
      }
      return reply(res, 405, { error: 'method' }); // no Allow
    }
    const m = path.match(/^\/items\/(\d+)$/);
    if (m) {
      if (!who) return reply(res, 401, { error: 'unauthorized' });
      const item = db.prepare('SELECT id, name, email FROM items WHERE id = ?').get(Number(m[1])); // no owner check
      if (!item) return reply(res, 404, { error: 'not found' });
      if (req.method === 'GET') return reply(res, 200, item);
      if (req.method === 'DELETE') { db.prepare('DELETE FROM items WHERE id = ?').run(item.id); return reply(res, 204); }
      return reply(res, 405, { error: 'method' });
    }
    return reply(res, 404, { error: 'not found' });
  } catch (e) {
    reply(res, 500, { error: String(e.stack) }); // leaks the stack
    if (/database is locked/.test(e.message)) setImmediate(() => { throw e; }); // a database error escapes the handler and kills the process
  }
}).listen(Number(port), '127.0.0.1', function listening() { console.log(`vulnerable on ${this.address().port}`); });
