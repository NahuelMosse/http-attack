# Severity

Every rule the script can emit; the finding id is `<rule>:<probe>:<target>`.

| Rule | Severity | Meaning |
|---|---|---|
| `process-died` | critical | the app stopped answering during a probe |
| `unauthenticated-access` | critical | a write or read is granted (2xx) without credentials |
| `idor` | critical | another user's credentials reach this user's object (2xx) |
| `sql-injection` | critical | an injected OR returns rows that a no-match control does not |
| `duplicates-stored` | critical | concurrent identical creates stored more than one distinct item |
| `file-served` | critical | a repo, secret or OS file came back over HTTP |
| `csrf` | critical | a cookie-authenticated write from a foreign Origin was accepted |
| `not-durable` | critical | a saved item is gone or different after a restart |
| `foreign-origin-accepted` | high | a request from a foreign Origin was accepted (`--origin-check always`) |
| `ambient-credentials` | high | with `--no-ambient`, a legitimate response sets Set-Cookie or asks WWW-Authenticate |
| `connection-dropped` | high | the connection was closed without a response while the app stayed up |
| `server-error` | high | a 5xx on client input (including path params, quotes and unique violations) |
| `accepted-invalid` | high | input that must be refused got a 2xx/3xx (bad JSON, invalid UTF-8, wrong type, other methods) |
| `no-body-limit` | high | a body over the limit is accepted, or a body that never ends is read forever |
| `double-slash-mismatch` | high | `//x` answers 2xx with something other than `/x` |
| `wildcard-unescaped` | high | `%` or `_` in a search reach LIKE as wildcards |
| `parser-accepted` | high | the HTTP parser let a malformed raw request through |
| `fault-not-reported` | high | a write during a database fault was not answered with a 5xx |
| `limit-counts-characters` | medium | the body limit counts characters, not bytes |
| `read-before-reject` | medium | a 50 MB body was read in full before the 415 |
| `media-type-strict` | medium | a case or parameter variant of the media type is refused (RFC 9110 8.3.1) |
| `stack-leak` | medium | a 5xx body leaks a stack trace, driver error or SQLSTATE |
| `parser-no-common-headers` | medium | a parser-level error lacks the app's common headers |
| `headers-missing` | medium | a response lacks a header every response must carry |
| `foreign-host-accepted` | medium | a request with a foreign Host was accepted (`--strict-host`; an info row without it) |
| `undocumented-status` | medium | with `--openapi`, the app answered a status the contract does not declare for that operation |
| `missing-allow` | low | 405 without an `Allow` header |
| `head-unsupported` | low | HEAD on a readable route answers 405 (RFC 9110 9.1) |
| `not-run` | - | a probe could not reach a verdict; never a pass |

A 5xx whose body leaks internals is reported twice on purpose: `server-error` (the app failed on client input) and `stack-leak`
(what the body disclosed) have different fixes and different owners, so each keeps its own id and can be suppressed on its own.
