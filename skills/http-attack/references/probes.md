# What the script probes

| Group | Probes | Correct response |
|---|---|---|
| input | truncated JSON, invalid UTF-8 inside a string, no `Content-Type`, `Application/JSON; charset=utf-8`, a string field sent as number/null/array/object, 1 MB body, limit+1 bytes of multibyte characters, PUT/DELETE/PATCH on the route | 4xx, never 5xx, nothing coerced or stored |
| paths | `//x` vs `/x`, `/%`, `?x=%FF%`, 30-digit numbers in query and path parameters (`/items/999...`, `/items/abc`, invalid UUID), HEAD/OPTIONS, `/.git/config`, `/.env`, `../../etc/passwd`, win.ini | 4xx or the same resource, never 5xx; files 404 |
| search | `%`, `_`, quotes, `\`, `' OR 1=1 --`, compared as parsed rows against a search that matches nothing | only rows containing the literal text |
| parser (raw socket) | `GARBAGE` request line, non-ASCII bytes in the path, an oversized header, `Content-Length` with `Transfer-Encoding` | 400/431 with the common headers, connection closed |
| resources | 50 MB `text/plain` to a JSON route, a chunked body that never ends (sends limit+1 bytes) | 415 at the first bytes; 413 at the limit or 408/close |
| concurrency | N identical creates released together (last-byte sync) | exactly one 201, the rest 409 |
| faults | a legitimate write while the database is locked or broken (`--fault-sqlite`, or `faultCmd` in the config) | 503/500 with a generic body, the process keeps answering |
| auth | each write and read without credentials; user B reads and deletes A's item (after checking B can use its own) | 401 (or a redirect to login); 404/403 for B |
| csrf | write with a foreign `Origin`, another port of the same host, `Origin: null` | 4xx |
| origin | `--origin-check always`: foreign Origin, another port, no `Sec-Fetch`, `Origin: null` with the given credentials; `--no-ambient`: no `Set-Cookie` or `WWW-Authenticate` | 4xx; no ambient credential |
| host | each write and read with `Host: attacker.example` | 4xx (421) |
| contract | `--openapi`: every status answered, per operation | a declared status |
| durability | create, restart, read back | same status and body |

Also check by hand what the script cannot: mass assignment (`"role":"admin"` on create/update), excessive data exposure, function-level
authorization (a regular user calling admin routes), rate limits on login, business-logic abuse (double-spend of a one-time token,
two updates with the same version, a counter below zero). Map findings to OWASP API Security Top 10 (API1, API2, API4, API5) and ASVS
level 1 for the security floor of a whole application.
