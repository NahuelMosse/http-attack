# http-attack

Adversarial probes against an HTTP API running on your machine, as an npm package with a CLI, and as a Claude Code skill that runs the same CLI.
Unit tests prove the handler does what you thought of; http-attack sends what you did not think of, against the real
server: malformed bodies, hostile paths, raw parser errors, concurrent duplicate creates, bodies that never end, LIKE and
SQL injection in search, database faults, missing authentication, IDOR and CSRF. Each failure is reported with a severity,
the response that would have been correct, and a stable id you can suppress with a reason.

Zero runtime dependencies. Node 22.13 or newer. Loopback hosts only.

> The probes create and delete rows, lock the database and send 50 MB bodies. Run them against a throwaway database, and
> remember that a tunnel (`kubectl port-forward`, `ssh -L`, a cloud SQL proxy) answers on `127.0.0.1` too.

## Install

```bash
npm i -D http-attack
```

## Usage

```bash
npx http-attack http://127.0.0.1:3000 \
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
example `server-error:path-param-letters:GET /items/{id}`; it never contains generated values. A row's `verdict` is `pass`,
`fail`, `not-run`, `skipped`, `suppressed` or `info` (reported, never a finding, never an exit 1); `rule` is `null` on every
row that is not a finding.

## Flags

`--help` prints the same list. Repeatable flags may be given several times.

| Flag | Value | Default | What it does |
|---|---|---|---|
| `--write` | `"<METHOD> <path> <body>"` | - | a request that creates or changes state, with a legitimate body (JSON, a form, or `@file`). Repeatable |
| `--read` | `"<path>"` | - | a request that returns data, with its query if any. Repeatable |
| `--search` | `"<path> <param>"` | - | a read with a free-text search parameter. Repeatable |
| `--unique` | `"<METHOD> <path> <body>"` | - | a create guarded by a unique key: N identical requests are sent at once. Repeatable |
| `--item-path` | `"/items/{id}"` | - | where a created item is read back when the create answers no `Location` |
| `--vary` | `<json-pointer \| field>` | the first string with an `@`, else the first string | the body field that keeps requests apart |
| `--content-type` | `<type>` | `application/json`, or a form | the media type of every write body |
| `--json` | - | - | send form bodies as JSON objects of the same fields |
| `--header` | `"Name: value"` | - | sent on every request (user A). Repeatable |
| `--auth-env` | `<VAR>` | - | sends `Authorization: Bearer $VAR` without the token on the command line |
| `--auth-header-name` | `<name>` | - | a custom header that carries credentials: removed in the no-credentials rows |
| `--other-header` | `"Name: value"` | - | user B's credentials, for the ownership (IDOR) rows. Repeatable |
| `--other-auth-env` | `<VAR>` | - | user B's bearer token from an environment variable |
| `--common-headers` | `"A, B"` | - | headers every response must carry, parser errors included |
| `--raw-exempt` | `"<why>"` | - | parser errors are answered by a proxy before the app: skip the common-header check there |
| `--body-limit` | `<bytes>` | - | the documented body limit |
| `--csrf` | - | - | the app authenticates with cookies: cross-origin writes must be refused |
| `--origin-check` | `always` or `cookie` | `cookie` | `always`: every write and read is also sent from a foreign Origin and must be refused; `cookie`: only the `--csrf` rows |
| `--no-ambient` | - | - | the API takes no credential a browser sends on its own: the origin rows become one check. Not with `--csrf` |
| `--host-check` | - | - | every write and read is also sent with a foreign Host; accepted, it is an info row |
| `--strict-host` | - | - | the same, and an accepted foreign Host is a finding |
| `--leak-path` | `<path>` | - | one more file the app must not serve. Repeatable |
| `--openapi` | `<file>` | - | every status the app answered must be one the contract declares |
| `--config` | `<file>` | `./http-attack.config.json` if present | per-route expectations and suppressions |
| `--ignore` | `<id>` | - | suppress a finding id, a rule name or `<rule>:<prefix>*`, added to the config's `ignore` list. Repeatable, or comma-separated |
| `--fault-sqlite` | `<file>` | - | holds `BEGIN EXCLUSIVE` on the app's SQLite file while the first `--write` is sent |
| `--persist-save` | `<file>` | - | create one item through the first `--write`, save how to read it back, then stop |
| `--persist-verify` | `<file>` | - | after a restart, read the saved item back and compare it |
| `--race-count` | `<n>` | `8` | identical requests per race |
| `--race-attempts` | `<n>` | `1` | races to try before concluding |
| `--hang-ms` | `<ms>` | `6000` | how long a never-ending body is waited for |
| `--format` | `text` or `json` | `text` | report format |
| `--help` | - | - | print the options |

## Programmatic use

```js
import { attack } from 'http-attack';

const report = await attack(['http://127.0.0.1:3000', '--write', 'POST /items {"name":"Ana"}', '--ignore', 'not-run:idor']);
console.log(report.exitCode, report.summary, report.rows.filter((row) => row.verdict === 'fail'));
```

`attack(argv, { cwd, env })` takes the command-line arguments and resolves to the report object (`base`, `rows`, `summary`,
`unusedIgnores`, `unusedRoutes`, `exitCode`) without printing or exiting. A bad argument or config rejects with an error
whose message says what to fix. `--help`, `--persist-save` and `--persist-verify` are command-line only. `renderText(report)`
and `renderJson(report)` produce the same output as the CLI.

## Config reference

`http-attack.config.json` in the project (or `--config <path>`):

```json
{
  "bodyLimit": 65536,
  "commonHeaders": ["x-request-id", "cache-control"],
  "authHeaderNames": ["x-auth-token"],
  "itemPath": "/items/{id}",
  "routes": {
    "/catalog": { "public": true, "reason": "public read-only catalogue" },
    "POST /imports": { "bodyLimit": 10485760, "invalidUtf8": "replace" },
    "POST /things": { "idempotentCreate": true, "reason": "ON CONFLICT DO NOTHING answers 200 with the same item" }
  },
  "ignore": [{ "id": "parser-accepted:big-header:raw", "reason": "the load balancer caps headers at 1 MB" }]
}
```

| Key | Meaning |
|---|---|
| `public` | for one route: reads and writes without credentials are expected to succeed. Needs a `reason` |
| `bodyLimit` | the documented body limit in bytes |
| `maxHeaderBytes` | the app's header limit; the oversized-header probe sends limit + 1 KB |
| `invalidUtf8` | `reject` (default) or `replace` (the parser substitutes U+FFFD by design) |
| `idempotentCreate` | for one route: several 2xx for one key are expected. Needs a `reason` |
| `vary`, `contentType` | the body field that keeps requests apart (JSON pointer), the media type of write bodies |
| `routes` | the settings above per path (`"/items"`), per request (`"POST /items"`) or per template (`"/items/{id}"`); `public` and `idempotentCreate` exist only here. `bodyLimit`, `maxHeaderBytes`, `invalidUtf8`, `vary`, `contentType` may also be top-level defaults |
| `commonHeaders`, `rawExempt`, `authHeaderNames`, `itemPath`, `persistIgnore` | as the flags of the same name |
| `faultCmd`, `faultRestore` | commands that break and heal the database. Preferred: a list, run without a shell (`["docker", "pause", "db"]`); a string runs through the system shell. Config only, never a flag |
| `persistDir` | a directory outside the working and temp directories where `--persist-save` may write |
| `writes`, `reads`, `searches`, `uniques` | the routes to attack; bodies as objects or `"@file"` |
| `ignore` | `{ id, reason }`: a finding id, a rule name, or `<rule>:<prefix>*`; it must start with a known rule. The reason is mandatory |

## CI

Depend on the package and run it in the pipeline, with the app started against a scratch database:

```yaml
- run: npm ci
- run: node app.mjs & # start the app on a scratch database
- run: curl --silent --output /dev/null --retry 30 --retry-connrefused --retry-delay 1 http://127.0.0.1:3000/ # the attack exits 2 if the app is not listening yet
- run: npx http-attack http://127.0.0.1:3000 --config http-attack.config.json --format json > attack.json
```

The step fails on exit 1 (findings) and exit 2 (could not run). The lockfile pins the version, so CI and the Claude Code
skill (which prefers the project's own copy) run the same probes.

## Claude Code skill

The repository is also a Claude Code plugin whose skill drives the CLI: it reads the router, builds the command, triages the rows and fixes the findings.

```bash
claude plugin marketplace add NahuelMosse/http-attack
claude plugin install http-attack@http-attack
```

Pin a release by adding the tag to the marketplace source:

```bash
claude plugin marketplace add NahuelMosse/http-attack#v1.2.0
```

Update with `claude plugin marketplace update http-attack`, then `claude plugin update http-attack@http-attack`.
Then ask Claude to break-test your local API ("my Express API is running on localhost:3000, try to break it before I ship").
When the project has `http-attack` in its `devDependencies`, the skill runs that copy; otherwise the one bundled in the skill (`skills/http-attack/scripts/`).

The skill directory is self-contained: `npx skills add NahuelMosse/http-attack` copies only `skills/http-attack/`, and it carries its own CLI, so a vendored copy runs without the npm package.

## Development

```bash
npm run test:unit                # no servers, seconds: the inner loop
npm run test:e2e                 # the fixtures and every test that starts a server
npm test                         # both
node tests/e2e-fixtures.mjs 3     # attack both fixtures three times: identical results, the fixed one clean
```

`tests/fixtures/` holds a deliberately broken API and its fixed twin; the vulnerable one must keep reporting
the ids pinned in `tests/expected-vulnerable.json`.

MIT licensed. See `skills/http-attack/NOTICES.md` for the ideas this builds on.
