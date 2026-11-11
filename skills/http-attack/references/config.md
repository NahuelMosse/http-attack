# Config file

`http-attack.config.json` in the project (or `--config <path>`) holds what the command line cannot say. Per-route settings
go under `routes` (key `"/items"`, `"POST /items"` or a template such as `"/items/{id}"`); `bodyLimit`, `maxHeaderBytes`,
`invalidUtf8`, `vary` and `contentType` may also be given at the top level for every route. `public` and `idempotentCreate` relax
a check, so they are accepted only inside one route and only with a `reason`:

```json
{
  "bodyLimit": 65536,
  "commonHeaders": ["x-request-id", "cache-control"],
  "routes": {
    "/catalog": { "public": true, "reason": "public read-only catalogue" },
    "/imports": { "bodyLimit": 10485760, "invalidUtf8": "replace" },
    "POST /things": { "idempotentCreate": true, "reason": "ON CONFLICT DO NOTHING answers 200 with the same item" }
  },
  "ignore": [
    { "id": "parser-accepted:big-header:raw", "reason": "the load balancer in front caps headers at 1 MB" }
  ]
}
```

| Setting | Meaning |
|---|---|
| `public` + `reason` | reads and writes of this route without credentials are expected to succeed (the reason is mandatory) |
| `bodyLimit` | the documented limit in bytes: the never-ending body sends limit+1 bytes, the multibyte probe is built from it |
| `maxHeaderBytes` | the app's header limit: the oversized-header probe sends limit+1 KB |
| `invalidUtf8` | `reject` (default) or `replace` (the parser substitutes U+FFFD by design) |
| `idempotentCreate` + `reason` | several 2xx for one key are expected (`ON CONFLICT DO NOTHING`); the reason is mandatory |
| `vary`, `contentType` | as the flags |
| `ignore` | `{id, reason}`: `id` is a finding id (shown in every report row), a rule name (`stack-leak`), `<rule>:<probe>` (every target of that probe), or `<rule>:<prefix>*`. It must start with a known rule and a reason is mandatory. `not-run` is never accepted alone: name the probe (`not-run:<probe>`) so one gap cannot hide the others. `--ignore <id>` on the command line adds ids to this list |

The config can also hold `faultCmd`, `faultRestore` (a list, run without a shell, or a string, run through the shell), `persistDir`, and list `writes`, `reads`, `searches`, `uniques` (bodies as objects or `"@file"`) and `persistIgnore`
(fields skipped when comparing the persisted item).
