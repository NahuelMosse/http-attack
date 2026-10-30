---
name: http-attack
description: Adversarially probe a running HTTP API on localhost to find the failures unit tests miss - 5xx on malformed input, parser errors that skip the app's common headers, duplicate creates under concurrency, unbounded or slow bodies, LIKE wildcards and SQL injection in search, a process that dies on a database fault, missing auth or object ownership (IDOR), data lost on restart. Use when the user asks to attack, harden, fuzz or break-test an API they run locally, or to check it "never answers 500". Not for static code review, load testing, OpenAPI contract conformance, or any host the user does not own.
---

# http-attack

Unit tests prove the handler does what the developer thought of. This skill sends what the developer did not think of,
against the real server, and reports each failure with its severity and the response that would have been correct.

**Scope and safety.** Only a server the user owns and runs on this machine (`localhost`, `127.0.0.1`, `::1`). The probes
create rows, delete rows, lock the database and send 50 MB bodies: never point them at shared, staging or production
hosts. Use a throwaway database file.

## Method

1. **Discover the surface.** Read the router (or the OpenAPI file) and list every route as one of: *create* (POST that
   stores), *update/delete*, *read one* (`/items/{id}`), *list*, *search* (list with a free-text parameter). Note for each:
   auth scheme (bearer, cookie, API key), the unique keys of the stored entity, the body limit, the database driver and
   file, and the headers every response is supposed to carry (request id, CORS, `Cache-Control`, security headers).
2. **Start the app** on a free port with a scratch database, and get two sets of credentials (user A and user B).
3. **Pick the probes by route kind** (catalogue below) and run them. `scripts/http-attack.mjs` runs the whole catalogue in
   one command; anything it does not cover (business-logic abuse, mass assignment of specific fields) is done by hand
   with `curl`.
4. **Classify each finding** with the severity table. A probe that could not reach a verdict (the legitimate body was
   refused, the app was down) is *not run*, never *passed*.
5. **Fix** at the right layer (guidance per finding below), not by special-casing the probe.
6. **Re-run the same command** until it reports 0 findings, and add a regression test per fixed finding to the app's
   own suite, so the next change cannot reintroduce it.

## The script

```bash
node scripts/http-attack.mjs http://127.0.0.1:3000 \
  --header "Authorization: Bearer $TOKEN_A" --other-header "Authorization: Bearer $TOKEN_B" \
  --write 'POST /items {"name":"Ana","email":"ana@example.com"}' \
  --read "/items?limit=10" --search "/items q" \
  --unique 'POST /items {"name":"Uno","email":"uno@example.com"}' \
  --common-headers "X-Request-Id, Cache-Control" --body-limit 65536 \
  --fault-sqlite ./data/app.db
```

Node 22.5+ (for `node:sqlite`), no dependencies. Every write body gets a per-run suffix on its email (or first free-text
field) so a uniqueness rule never answers in place of the defense under test. Exit 0 = no findings, 1 = findings,
2 = could not run. `--format json` for machine output. Persistence is a two-step run around a restart:
`--persist-save state.json`, restart the app, `--persist-verify state.json`. On Git Bash for Windows set
`MSYS_NO_PATHCONV=1` so `/items` is not rewritten into a Windows path, and give the app and `--fault-sqlite` the same
absolute Windows path (`D:/app/data/app.db`), so both open the same file. The comment block at the top of
`scripts/http-attack.mjs` lists every option.

## Severity

| Severity | Meaning | Examples |
|---|---|---|
| critical | data or access is compromised, or the process dies | IDOR, unauthenticated access, SQL injection, duplicates stored, crash on DB fault, repo file served |
| high | the server fails on input it must refuse | any 5xx on client input, unique violation as 500, body never cut, wrong type coerced and stored |
| medium | correct refusal, wrong shape or cost | parser errors without common headers, 50 MB read before the 415, charset refused, stack in the 5xx body |
| low | protocol detail | 405 without `Allow` |

## Catalogue: probe, correct response, fix

### Malformed input (every create/update)
| Probe | Correct | Fix |
|---|---|---|
| Truncated JSON `{"x":` | 400, the app's error body | catch the parse error in the body middleware |
| Invalid UTF-8 bytes inside a string | 400; nothing stored with U+FFFD | decode with `TextDecoder('utf-8', { fatal: true })` or the framework's strict option |
| JSON with no `Content-Type` | 415 (never 5xx) | read the header defensively: `(h ?? '').split(';')[0]` |
| `Application/JSON; charset=utf-8` | accepted | compare the media type lowercased, without parameters (RFC 9110 §8.3.1) |
| A string field sent as number, `null`, array, object | 400/422, never coerced | validate types with a schema; never `String(x)` user input |
| 1 MB body, and limit+1 bytes made of multibyte chars | 413 | count **bytes** while reading, not characters after decoding |
| PUT/DELETE/PATCH on a route that does not take them | 405 with `Allow` | let the router answer 405 and set `Allow` |

### Parser-level errors (raw socket)
| Probe | Correct | Fix |
|---|---|---|
| `GARBAGE` request line; raw non-ASCII bytes in the path | 400 + the common headers, connection closed | handle the server's parser-error hook (Node `clientError`, a custom h11/uvicorn handler, the proxy's error page) and write the same headers there |
| 20 KB header | 431 + common headers | same hook; do not raise the header limit to make it pass |
| `Content-Length` and `Transfer-Encoding` together | 400 | keep the HTTP server's strict parsing on (request smuggling) |

These answers come from the HTTP parser, before any middleware: a request-id, CORS or security-header middleware never
sees them. If a proxy answers them by design, pass `--raw-exempt "<why>"` and check the proxy instead.

### Paths and query
| Probe | Correct | Fix |
|---|---|---|
| `//`, `//items` | 404 or the same resource, never 5xx | do not feed `req.url` to `new URL(path, base)`: `//x` is parsed as a host |
| `/items/%`, `?x=%FF%` | 400 | wrap `decodeURIComponent`; return 400 on `URIError` |
| Numeric param as 30 nines, its negative, `1e3`, empty | 400 (or clamped 2xx) | accept `^[0-9]+$` up to a cap; never interpolate numbers into SQL |
| `HEAD`/`OPTIONS` on each route | 2xx, or 405 with `Allow` | router default |
| `/.git/config`, `/.env`, `/package.json`, `../../etc/passwd` | 404 | serve static files from a dedicated directory, never the repo root |

### Search
| Probe | Correct | Fix |
|---|---|---|
| `%`, `_` | only rows containing that literal character | bind the term as a parameter and escape `\ % _` with `LIKE ? ESCAPE '\'` |
| `'`, `"`, `\` | 200 | parameters, never string-built SQL |
| `' OR 1=1 --`, `%' OR '1'='1` | 200 with no rows (no row contains that text) | parameters; a 5xx or "every row" is an injection |

The wildcard check needs at least one stored row; the script creates it through `--write` first.

### Concurrency
| Probe | Correct | Fix |
|---|---|---|
| 8 identical creates on a unique key, released together (last-byte sync) | exactly one 201, seven 409 | a `UNIQUE` constraint in the database, and map its violation error to 409; check-then-insert in the app is not enough |

Also try by hand where the domain has it: double-spend of a one-time token, two updates with the same version
(expect one 409/412), a counter decremented below zero.

### Resources
| Probe | Correct | Fix |
|---|---|---|
| 50 MB `text/plain` to a JSON route | 415 at the first bytes (well under 2 s) | check `Content-Type` before reading the body |
| JSON body that never ends (chunked) | 413 at the limit, or 408 / close within the request timeout | a byte limit in the body reader, and server request/header timeouts |

### Faults and durability
| Probe | Correct | Fix |
|---|---|---|
| A write while the SQLite file is held with `BEGIN EXCLUSIVE` | 503 (or 500) with the generic body and common headers; the process keeps answering | await every DB call inside the handler's error boundary; no fire-and-forget writes; a global `unhandledRejection` logger is a backstop, not the fix |
| 5xx body content | `{"error":"internal"}`-style, no stack, no driver message | log the error server-side, answer a fixed body |
| Create, restart the process, read back | same status and body | commit before answering; no in-memory store; migrations run on start |

For other databases, simulate the fault by hand: stop the container mid-request, revoke write permission, fill the
connection pool. The expected behaviour is the same.

### Authentication and ownership (OWASP API1, API2, API5)
| Probe | Correct | Fix |
|---|---|---|
| Each write and read without credentials | 401 | auth middleware on the router, deny by default |
| User B reads and deletes user A's item (`Location` of A's create) | 404 (or 403) | scope every query by owner: `WHERE id = ? AND owner = ?` |
| `--csrf` (cookie auth only): write with a foreign `Origin`, another port of the same host, `Origin: null` | 403 | check `Origin` against the app's own origin; `SameSite` alone does not cover same-site, other-port pages |

Not automated, check by hand: mass assignment (send `"role":"admin"`, `"owner":"bob"` on create and update; expect it
ignored), excessive data exposure (responses carry no hash, token or internal field), function-level authorization
(a regular user calling admin routes), rate limits on login and expensive endpoints.

## Reading the report

Each line is `pass`, `FAIL <severity>` or `NOT RUN`, with the status seen; a failure adds `expected:` and `evidence:`.
Fix critical and high first. A `NOT RUN` row says why (the legitimate body was refused, the list was empty): fix the
input and run again; it is never a pass. For the security floor of a whole application, map the findings to the
OWASP ASVS level 1 requirements (V2 validation, V4 API, V8 authorization, V13 configuration) and test the rest there.

## What this skill does not do

- Contract conformance against an OpenAPI schema and property-based generation of inputs: use Schemathesis.
- Stateful sequence fuzzing over a whole API: use RESTler.
- Known-CVE and misconfiguration scanning of the stack: OWASP ZAP API scan or Nuclei templates.
- Content discovery of unlinked routes: ffuf with a wordlist.
- Load and latency limits: a load tool, not this.
