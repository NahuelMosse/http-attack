// Throwaway in-memory servers, each with one behaviour that a probe must treat correctly. Every option is off by default,
// which gives a well-behaved API: `GET/POST /items` (bearer "alice" or "bob"), `GET /items/:id`, and `GET /health`.
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';

const TOKENS = { 'Bearer alice': 'alice', 'Bearer bob': 'bob' };

export async function startQuirkServer(q = {}) {
  const items = [];
  const things = [];
  let seq = 0;
  const requests = [];
  const json = (res, s, body, extra = {}) => {
    if (res.headersSent) return;
    res.writeHead(s, { 'content-type': 'application/json', 'x-request-id': 'r', 'cache-control': 'no-store', ...extra });
    res.end(body === undefined ? '' : JSON.stringify(body));
  };
  const readBody = (req) => (req.cachedBody ??= new Promise((done) => { const parts = []; let size = 0; req.on('data', (d) => { size += d.length; if (q.noLimit || size < (q.keep ?? 1 << 20)) parts.push(d); }); req.on('end', () => { req.overflow = size >= (q.keep ?? 1 << 20) && !q.noLimit; done(Buffer.concat(parts)); }); }));
  const unauthorized = (res) => (q.loginRedirect ? json(res, 302, undefined, { location: '/login' }) : json(res, 401, { error: 'unauthorized' }));

  const server = createServer(q.maxHeaderSize ? { maxHeaderSize: q.maxHeaderSize } : {}, async (req, res) => {
    requests.push({ method: req.method, url: req.url, headers: req.headers });
    if (q.streamLimit && req.method === 'POST') {
      let n = 0;
      req.on('data', (d) => { n += d.length; if (n > q.streamLimit) json(res, 413, { error: 'too large' }, { connection: 'close' }); });
    }
    try {
      const url = new URL(req.url, 'http://x');
      const path = url.pathname;
      if (path === '/' || path === '/health') return json(res, 200, { ok: true });
      if (path === '/login') return json(res, 200, { login: true });
      if (q.repoFile && path === '/.git/config') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('[core]\n\tbare = false\n'); }
      if (q.publicRead && path === '/catalog') return json(res, 200, [{ id: 1, name: 'one' }]);
      if (q.openWrite && path === '/open' && req.method === 'POST') { await readBody(req); return json(res, 201, { id: ++seq }, { location: `/open/${seq}` }); }
      if (q.faultFile && existsSync(q.faultFile) && req.method === 'POST') return q.faultIgnored ? json(res, 201, { id: ++seq }) : json(res, 500, { error: 'internal' });

      if (q.csrf422 && req.method === 'POST' && req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) return json(res, 422, { error: 'invalid authenticity token' });
      if (q.requireQ && path === '/items' && req.method === 'GET' && url.searchParams.get('q') === null) return json(res, 400, { error: 'q is required' });
      if (q.noHead && req.method === 'HEAD') { res.writeHead(405, q.noHead === 'allow' ? { allow: 'GET, POST' } : {}); return res.end(); }
      if (q.dropBadJson && req.method === 'POST' && (await readBody(req)).toString() === '{"x":') return req.socket.destroy();
      const who = q.authHeader ? (req.headers[q.authHeader] === 'alice-token' ? 'alice' : req.headers[q.authHeader] === 'bob-token' ? 'bob' : undefined) : (TOKENS[req.headers.authorization] ?? { 'session=alice': 'alice', 'session=bob': 'bob' }[req.headers.cookie]);

      if (path === '/things' && req.method === 'POST') { // POST that stores without a unique key, or idempotently
        if (!who) return unauthorized(res);
        const b = JSON.parse((await readBody(req)).toString() || '{}');
        if (q.storedDuplicates || q.idempotentCreate) {
          await new Promise((r) => setTimeout(r, 20));
          const hit = q.idempotentCreate && things.find((t) => t.key === b.key);
          if (hit) return json(res, 200, hit, { location: `/things/${hit.id}` });
          const t = { id: ++seq, key: b.key };
          things.push(t);
          return json(res, 201, t, { location: `/things/${t.id}` });
        }
      }

      const m = path.match(/^\/items(?:\/([^/]*))?$/);
      if (m) {
        if (!who && !(q.publicItems && req.method === 'GET')) return unauthorized(res);
        if (m[1] !== undefined) {
          if (q.pathParam500 && !/^\d+$/.test(m[1])) throw new Error(`invalid id ${m[1]}\n    at lookup (/app/src/items.js:10:5)`);
          const it = items.find((i) => String(i.id) === m[1] && i.owner === who);
          return it ? json(res, 200, it) : json(res, 404, { error: 'not found' });
        }
        if (req.method === 'GET') {
          let rows = items.filter((i) => i.owner === who);
          const term = url.searchParams.get('q');
          if (term !== null && !(q.likeWild && (term === '%' || term === '_'))) rows = rows.filter((i) => i.name.includes(term));
          return json(res, 200, q.envelope ? { requestId: Math.random(), query: term, data: rows } : rows);
        }
        if (req.method === 'POST') {
          const type = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
          const want = q.jsonApi ? 'application/vnd.api+json' : 'application/json';
          if (q.jsonApi ? req.headers['content-type'] !== want : type !== want) return json(res, 415, { error: 'media type' });
          const buf = await readBody(req);
          if (req.overflow) return json(res, 413, { error: 'too large' });
          let text;
          if (q.utf8Replace) text = buf.toString('utf8'); else try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { return json(res, 400, { error: 'utf8' }); }
          if (buf.length >= (q.keep ?? 1 << 20) && !q.noLimit) return json(res, 413, { error: 'too large' });
          let b; try { b = JSON.parse(text); } catch { return json(res, 400, { error: 'json' }); }
          const f = q.nested ? b?.item : q.jsonApi ? b?.data?.attributes : b;
          if (!f || typeof f.name !== 'string' || typeof f.email !== 'string') return json(res, 400, { error: 'invalid' });
          if (items.some((i) => i.email === f.email)) return json(res, 409, { error: 'exists' });
          const it = { id: ++seq, owner: who, name: f.name, email: f.email };
          items.push(it);
          return json(res, 201, it, q.noLocation ? {} : { location: `/items/${it.id}` });
        }
        return json(res, 405, { error: 'method' }, { allow: 'GET, POST' });
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      json(res, 500, q.stackLeak === false ? { error: 'internal' } : { error: String(e.stack ?? e) });
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { requests, port: server.address().port, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
