# http-attack

Adversarial probes against an HTTP API running on your machine, as a Claude Code plugin and as a standalone CLI.
Unit tests prove the handler does what you thought of; http-attack sends what you did not think of, against the real
server: malformed bodies, hostile paths, raw parser errors, concurrent duplicate creates, bodies that never end, LIKE and
SQL injection in search, database faults, missing authentication, IDOR and CSRF. Each failure is reported with a severity,
the response that would have been correct, and a stable id you can suppress with a reason.

Zero runtime dependencies. Node 22.13 or newer. Loopback hosts only.

> The probes create and delete rows, lock the database and send 50 MB bodies. Run them against a throwaway database, and
> remember that a tunnel (`kubectl port-forward`, `ssh -L`, a cloud SQL proxy) answers on `127.0.0.1` too.

## Install as a Claude Code plugin

```bash
claude plugin marketplace add NahuelMosse/http-attack
claude plugin install http-attack@http-attack
```

Pin a release by adding the tag to the marketplace source:

```bash
claude plugin marketplace add NahuelMosse/http-attack#v1.0.0
```

Update with `claude plugin marketplace update http-attack`, then `claude plugin update http-attack@http-attack`.

Then ask Claude to break-test your local API ("my Express API is running on localhost:3000, try to break it before I ship").

## Standalone CLI

```bash
git clone https://github.com/NahuelMosse/http-attack && cd http-attack
node skills/http-attack/scripts/http-attack.mjs http://127.0.0.1:3000 \
  --header "Authorization: Bearer $TOKEN_A" --other-header "Authorization: Bearer $TOKEN_B" \
  --write 'POST /items {"name":"Ana","email":"ana@example.com"}' \
  --read "/items?limit=10" --search "/items q" \
  --unique 'POST /items {"name":"Uno","email":"uno@example.com"}' \
  --item-path "/items/{id}" --common-headers "X-Request-Id, Cache-Control" --body-limit 65536
```

`--help` lists every option. In Windows PowerShell 5.1 put JSON bodies in a file (`--write "POST /items @body.json"`),
because PowerShell strips the quotes of inline JSON; a body that does not parse exits 2 and shows what arrived.

Exit codes: `0` no findings (after suppressions), `1` findings, `2` the run could not complete (crash, invalid argument,
app down, no probe run, or a probe that could not run).

`--format json` prints `{ schemaVersion: 1, summary, findings, rows }`. A finding id is `<rule>:<probe>:<target>`, for
example `server-error:path-param-letters:GET /items/{id}`; it never contains generated values.

## Config reference

`http-attack.config.json` in the project (or `--config <path>`):

```json
{
  "bodyLimit": 65536,
  "commonHeaders": ["x-request-id", "cache-control"],
  "authHeaderNames": ["x-auth-token"],
  "itemPath": "/items/{id}",
  "routes": {
    "/catalog": { "public": true },
    "POST /imports": { "bodyLimit": 10485760, "invalidUtf8": "replace" },
    "POST /things": { "idempotentCreate": true }
  },
  "ignore": [{ "id": "parser-accepted:big-header:raw", "reason": "the load balancer caps headers at 1 MB" }]
}
```

| Key | Meaning |
|---|---|
| `public` | reads and writes without credentials are expected to succeed |
| `bodyLimit` | the documented body limit in bytes |
| `maxHeaderBytes` | the app's header limit; the oversized-header probe sends limit + 1 KB |
| `invalidUtf8` | `reject` (default) or `replace` (the parser substitutes U+FFFD by design) |
| `idempotentCreate` | several 2xx for one key are expected |
| `vary`, `contentType` | the body field that keeps requests apart (JSON pointer), the media type of write bodies |
| `routes` | the settings above per path (`"/items"`) or per request (`"POST /items"`); top-level keys are defaults |
| `commonHeaders`, `rawExempt`, `authHeaderNames`, `itemPath`, `persistIgnore` | as the flags of the same name |
| `writes`, `reads`, `searches`, `uniques` | the routes to attack; bodies as objects or `"@file"` |
| `ignore` | `{ id, reason }`: a finding id, a rule name, or a prefix ending in `*`. The reason is mandatory |

## CI

```yaml
- run: node skills/http-attack/scripts/http-attack.mjs http://127.0.0.1:3000 --config http-attack.config.json --format json > attack.json
```

The step fails on exit 1 (findings) and exit 2 (could not run). Start the app with a scratch database before it.

## Development

```bash
npm test                         # unit and integration tests
node test/e2e-fixtures.mjs 3     # attack both fixtures three times: identical results, the fixed one clean
```

`skills/http-attack/fixtures/` holds a deliberately broken API and its fixed twin; the vulnerable one must keep reporting
the ids pinned in `test/expected-vulnerable.json`.

MIT licensed. See `NOTICES.md` for the ideas this builds on.
