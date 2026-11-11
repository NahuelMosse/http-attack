---
name: http-attack
description: Break-test an HTTP API the user runs locally before shipping it. Sends malformed bodies, hostile paths, raw parser errors, concurrent duplicate creates, never-ending bodies, LIKE/SQL injection in search, database faults, missing auth, IDOR and CSRF, and reports each failure with its severity and the correct response. Use when asked to attack, harden, fuzz or break-test a local API, or to check it never answers 500. Not for code review, load tests, full OpenAPI conformance, or hosts the user does not own.
---

# http-attack

Unit tests prove the handler does what the developer thought of. This skill sends what the developer did not think of,
against the real server, and reports each failure with its severity and the response that would have been correct.

## Scope and safety

- Only an app the user owns, running on this machine (`localhost`, `127.0.0.1`, `::1`). The script refuses other hosts.
- **Loopback is not proof the app is local.** `kubectl port-forward`, `ssh -L`, a cloud SQL proxy or a dev tunnel all answer on
  `127.0.0.1` while the data lives elsewhere. Confirm with the user that the app behind the port is a local process.
- The probes create about 20-40 rows per write route, delete rows, lock the database and send 50 MB bodies. **Use a
  throwaway database** (a scratch SQLite file, or a Postgres/MySQL database created for this run), never one with data
  that matters. If you cannot confirm it is throwaway, stop and ask.

## Method

1. **Discover the surface.** Read the router (or the OpenAPI file) and list every route as one of: *create* (POST that
   stores), *update/delete*, *read one* (`/items/{id}`), *list*, *search* (list with a free-text parameter). Note per route: the
   auth scheme (bearer, cookie, API key, custom header), the unique keys of the stored entity, the body limit, the
   database, the maximum header size, whether the route is public by design, and the headers every response must carry
   (request id, `Cache-Control`, security headers).
2. **Start the app** on a free port with the scratch database and get credentials for two users (see below).
3. **Run the script** (below) with one `--write` per create/update route, `--read` per list, `--search` per search route,
   `--unique` per create guarded by a unique key.
4. **Triage every row.** `FAIL` is a finding; `NOT RUN` is a probe that could not reach a verdict (the legitimate body was
   refused, no item route is known, no rows to search): fix the input and run again, it is never a pass. A finding that is
   correct behaviour for this app is not a bug: say so and suppress it in the config with the reason (`references/config.md`), do not
   change the app to satisfy the probe.
5. **Fix** real findings at the right layer (`references/fixes.md` has the fix per finding and stack), not by special-casing
   the probe. Add a regression test per fixed finding to the app's own suite.
6. **Re-run the same command** until it reports **0 findings, or every remaining one is suppressed in the config with its
   reason**, and no row is `NOT RUN` (or each is suppressed with a reason). Exit code 0 means exactly that.
7. **Clean up**: the run left rows in the scratch database; drop the database (or the file), do not reuse it.

## Running it

If the project lists `http-attack` in its `devDependencies`, run `npx --no-install http-attack` instead of
`node "${CLAUDE_SKILL_DIR}/scripts/http-attack.mjs"` in every command below: it is the version CI runs. Without that
dependency, use the copy bundled with this skill, as written.

Git Bash / macOS / Linux:

```bash
MSYS_NO_PATHCONV=1 node "${CLAUDE_SKILL_DIR}/scripts/http-attack.mjs" http://127.0.0.1:3000 \
  --header "Authorization: Bearer $TOKEN_A" --other-header "Authorization: Bearer $TOKEN_B" \
  --write 'POST /items {"name":"Ana","email":"ana@example.com"}' \
  --read "/items?limit=10" --search "/items q" \
  --unique 'POST /items {"name":"Uno","email":"uno@example.com"}' \
  --item-path "/items/{id}" --common-headers "X-Request-Id, Cache-Control" --body-limit 65536 \
  --fault-sqlite ./data/app.db
```

Windows PowerShell (5.1 strips the quotes inside inline JSON, so put bodies in files):

```powershell
Set-Content -Encoding ascii body.json '{"name":"Ana","email":"ana@example.com"}'
node "${CLAUDE_SKILL_DIR}/scripts/http-attack.mjs" http://127.0.0.1:3000 `
  --header "Authorization: Bearer $env:TOKEN_A" --write "POST /items @body.json" --read "/items?limit=10"
```

An inline JSON body that does not parse exits 2 and shows what arrived. `node "${CLAUDE_SKILL_DIR}/scripts/http-attack.mjs" --help` lists every option.
Notes:

- Zero dependencies; Node 22.13 or newer.
- Every write body gets a per-run suffix on one string field (the first containing `@`, else the first string; `--vary /item/email`
  picks another, also nested) so a uniqueness rule never answers in place of the defense under test.
- `--content-type application/vnd.api+json` for non-default media types; `--auth-header-name X-Auth-Token` when credentials
  travel in a custom header; `--auth-env VAR` / `--other-auth-env VAR` keep tokens off the command line.
- Cookie authentication: add `--csrf` and pass the cookie with `--header "Cookie: ..."`.
- `--origin-check always` sends every write and read from a foreign Origin (another site, another port, no `Sec-Fetch`,
  `Origin: null`) with the given credentials, cookie or not; each must be refused. A 409, 422 or 400 there is `NOT RUN`: the
  body was judged, not the origin. `--no-ambient` declares that no credential a browser sends on its own reaches the API: the
  origin rows are replaced by one check (no legitimate response sets `Set-Cookie` or asks `WWW-Authenticate`).
- `--host-check` also sends every write and read with a foreign `Host` (after a read answered 2xx legitimately). Accepted, it is
  an `info` row; with `--strict-host` it is a finding. A 409 or 422 there is `NOT RUN`.
- `--ignore <id>` (repeatable, or comma-separated) suppresses a finding id, rule or `<rule>:<prefix>*` for this run, as the config's `ignore` does; the config's reason rule
  does not apply, so prefer the config for anything that outlives the run.
- `--leak-path /backup.sql` (repeatable) adds a file the app must not serve: a 2xx with a non-HTML body is `file-served`.
- A body that never ends is sent chunked and with a large `Content-Length`; with a declared body limit only a 413 passes.
  HEAD goes to write-only routes too (a 405 with `Allow` is fine, a 5xx is not). In the race a 3xx counts as a success.
- `--json` sends form bodies as JSON objects. Without it, a form write whose legitimate request answers 415 is sent as JSON
  from then on, and the `legit-write` row says so.
- `--openapi openapi.yaml` checks every status the app answered against the statuses the contract declares for that
  operation (the most specific template; `2XX` and `default` count). A path the contract lacks is not judged.
- Persistence is a two-step run around a restart: `--persist-save state.json`, restart the app, `--persist-verify state.json` (the file must be inside the working or temp
  directory, or the config must name its directory in `persistDir`).
- Other databases: `faultCmd` (`["docker", "pause", "db"]`) and `faultRestore` (`["docker", "unpause", "db"]`) in the config file: the
  command that breaks the database and the one that heals it (the restore always runs). Prefer the list form: it runs without a shell, so
  there is no quoting or expansion and it behaves the same on Windows and POSIX. A string (`"docker pause db"`) runs through the system shell.
  They are read only from the config file, never from the command line: have the user review them before the run.
- On Git Bash for Windows set `MSYS_NO_PATHCONV=1` so `/items` is not rewritten into a Windows path, and give the app and
  `--fault-sqlite` the same absolute Windows path (`D:/app/data/app.db`).

**Two users' tokens.** Use the app's own seed or signup: create two users (alice, bob) against the scratch database, log in
as each, and export the tokens (`TOKEN_A`, `TOKEN_B`) or the session cookies. If the app has no login, a test helper that
signs a token for two different user ids works. The ownership rows need both; without user B they are skipped.

## Reading the report

Each row is `pass`, `FAIL <severity>`, `NOT RUN`, `suppressed`, `skipped` (the config says it does not apply) or `info`
(seen, neither a pass nor a finding). Failures show
`expected:`, `evidence:` and an `id:` that is stable between runs. `--format json` prints `{schemaVersion: 1, summary, findings,
rows}`; the summary counts `run`, `passed`, `failed`, `suppressed`, `notRun`, `skipped`, `info` and findings by severity.
Exit codes: `0` no findings, `1` findings, `2` the run could not complete (bad argument, app down, crash, zero probes run, or
some probe not run).

## References

Read them when the run needs them:

- `references/severity.md`: every rule the script emits, with its severity.
- `references/probes.md`: what each probe group sends and the response that passes.
- `references/config.md`: the `http-attack.config.json` settings and how to suppress a finding with a reason.
- `references/fixes.md`: the fix per finding and stack.

## What this skill does not do

- Schema conformance against an OpenAPI file (only statuses are checked) and property-based input generation: Schemathesis.
- Stateful sequence fuzzing over a whole API: RESTler.
- Known-CVE and misconfiguration scanning of the stack: OWASP ZAP API scan or Nuclei templates.
- Content discovery of unlinked routes: ffuf with a wordlist.
- Load and latency limits: a load tool.
