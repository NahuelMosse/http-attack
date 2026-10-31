// Throwaway server that answers an oversized POST with 413 (Content-Length, Connection: close) once 256 KB of the body
// arrived: the status line first, the body 30 ms later, then it destroys the socket while the client is still sending.
// Everything else answers 2xx.
import { createServer } from 'node:http';

const LIMIT = 64 * 1024;
const BODY = JSON.stringify({ error: 'too large' });
const HEAD = `HTTP/1.1 413 Payload Too Large\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(BODY)}\r\nconnection: close\r\n\r\n`;

export async function startEarlyCloseServer() {
  const server = createServer((req, res) => {
    if (req.method === 'POST' && Number(req.headers['content-length'] ?? 0) > LIMIT) {
      let seen = 0, refused = false;
      req.on('data', (d) => {
        seen += d.length;
        if (seen < LIMIT * 4 || refused) return;
        refused = true;
        req.pause(); // the client stays mid-upload until the socket goes
        const sock = req.socket;
        sock.write(HEAD, () => setTimeout(() => sock.write(BODY, () => sock.destroy()), 30));
      });
      req.on('error', () => {});
      return;
    }
    req.resume();
    req.on('end', () => {
      res.writeHead(req.method === 'POST' ? 201 : 200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 1 }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }) };
}
