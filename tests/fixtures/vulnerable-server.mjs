// A deliberately broken API, to prove that http-attack finds what it claims to find.
// node vulnerable-server.mjs <port | 0> <sqlite-file | :memory:>   Users: "Authorization: Bearer alice" / "Bearer bob", or "Cookie: session=alice" / "session=bob".
// Every defect below is one the script must report. Do not copy this code.
//
// Defects and the finding ids each produces. tests/expected-vulnerable.json pins the same ids; a test keeps both in step.
// A 5xx that leaks a stack is two ids on purpose: server-error (the app failed) and stack-leak (what the body disclosed).
//
// [D1] a "//" or "%" in the path throws in the URL parsing, and "//items" is not "/items"
//   id: server-error:double-slash:GET /
//   id: stack-leak:double-slash:GET /
//   id: double-slash-mismatch:double-slash:GET /items
//   id: double-slash-mismatch:double-slash:GET /notes
//   id: server-error:percent-path:GET /
//   id: server-error:percent-path:GET /items
//   id: server-error:percent-path:GET /notes
//   id: stack-leak:percent-path:GET /
//   id: stack-leak:percent-path:GET /items
//   id: stack-leak:percent-path:GET /notes
// [D2] a POST without Content-Type crashes the handler
//   id: server-error:no-content-type:POST /items
//   id: stack-leak:no-content-type:POST /items
// [D3] the "limit" parameter goes into the SQL unchecked, so a huge or negative one is a SQL error
//   id: server-error:number-limit-999999:GET /items?limit=10
//   id: server-error:number-limit--99999:GET /items?limit=10
//   id: stack-leak:number-limit-999999:GET /items?limit=10
//   id: stack-leak:number-limit--99999:GET /items?limit=10
// [D4] the search term is concatenated into the SQL: wildcards pass through, a quote breaks it, an injected OR returns rows
//   id: server-error:quote-single:GET /items
//   id: stack-leak:quote-single:GET /items
//   id: sql-injection:injection-or-number:GET /items
//   id: sql-injection:injection-or-string:GET /items
//   id: wildcard-unescaped:percent:GET /items
//   id: wildcard-unescaped:underscore:GET /items
// [D5] check-then-insert without a transaction: the UNIQUE violation of a race escapes as a 500
//   id: server-error:race-identical-creates:POST /items
//   id: stack-leak:race-identical-creates:POST /items
// [D6] /notes has no authentication and no owner: anyone reads it, and user B reads what user A created
//   id: unauthenticated-access:write-without-credentials:POST /notes
//   id: unauthenticated-access:item-without-credentials:GET /notes/{id}
//   id: idor:idor-get:GET /notes/{id}
// [D7] /notes has no unique key: identical creates are all stored
//   id: duplicates-stored:race-identical-creates:POST /notes
// [D8] no Origin check on writes (CSRF)
//   id: csrf:origin-another-site:POST /items
//   id: csrf:origin-another-port:POST /items
//   id: csrf:origin-null-origin:POST /items
//   id: csrf:origin-another-site:POST /notes
//   id: csrf:origin-another-port:POST /notes
//   id: csrf:origin-null-origin:POST /notes
// [D9] no body limit: a large body and a body that never ends are read whole
//   id: no-body-limit:body-1mb:POST /items
//   id: no-body-limit:body-1mb:POST /notes
//   id: no-body-limit:body-never-ends:POST /items
//   id: no-body-limit:body-never-ends-length:POST /items
//   id: no-body-limit:body-never-ends:POST /notes
//   id: no-body-limit:body-never-ends-length:POST /notes
// [D10] the body is read before the Content-Type is looked at (/notes never looks at it)
//   id: read-before-reject:text-plain-50mb:POST /items
//   id: read-before-reject:text-plain-50mb:POST /notes
// [D11] invalid UTF-8 is replaced silently and a non-string name is coerced
//   id: accepted-invalid:invalid-utf8:POST /items
//   id: accepted-invalid:invalid-utf8:POST /notes
//   id: accepted-invalid:wrong-type-number-name:POST /items
//   id: accepted-invalid:wrong-type-array-name:POST /items
//   id: accepted-invalid:wrong-type-object-name:POST /items
// [D12] the media type is compared case-sensitively
//   id: media-type-strict:media-type-variant:POST /items
// [D13] 405 without an Allow header, and HEAD is not supported
//   id: missing-allow:method-put:POST /items
//   id: missing-allow:method-delete:POST /items
//   id: missing-allow:method-patch:POST /items
//   id: missing-allow:options:OPTIONS /items
//   id: missing-allow:head:HEAD /items
//   id: head-unsupported:head:HEAD /items
// [D14] /items/{id} has no owner check: another user reads and deletes the item
//   id: idor:idor-get:GET /items/{id}
//   id: idor:idor-delete:DELETE /items/{id}
// [D15] the repository is served
//   id: file-served:file-served:GET /.git/config
// [D16] no 'clientError' handler: parser-level answers lack the common headers
//   id: parser-no-common-headers:garbage-request-line:raw
//   id: parser-no-common-headers:non-ascii-path:raw
//   id: parser-no-common-headers:big-header:raw
//   id: parser-no-common-headers:cl-te-conflict:raw
// [D17] a locked database throws outside the handler and kills the process
//   id: process-died:database-fault:POST /items
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const [port, file] = process.argv.slice(2);
const db = new DatabaseSync(file);
db.exec('PRAGMA synchronous = OFF'); // durability is irrelevant for a fixture; skipping the fsync keeps writes fast on a slow disk
db.exec('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, owner TEXT, name TEXT, email TEXT UNIQUE); CREATE TABLE IF NOT EXISTS audit (at TEXT); '
  + 'CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT)');

const reply = (res, status, body, extra = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', 'x-request-id': randomUUID(), 'cache-control': 'no-store', ...extra });
  res.end(body === undefined ? '' : JSON.stringify(body));
};
// Bearer tokens or a session cookie (session=alice / session=bob): the cookie is what the CSRF probes attack.
const userOf = (req) => ({ 'Bearer alice': 'alice', 'Bearer bob': 'bob' })[req.headers.authorization] ?? ({ 'session=alice': 'alice', 'session=bob': 'bob' })[req.headers.cookie];
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
