# Changelog

## Unreleased

- `--origin-check always`, `--no-ambient`, `--host-check` / `--strict-host`, `--openapi <file>`, `--json` and a repeatable
  `--leak-path`. A read's origin and host rows run only after its legitimate request answered 2xx.
- The never-ending body is also sent with a large `Content-Length`; with a declared limit a reset instead of a 413 is a finding.
- HEAD is sent to write-only routes too; the race counts a 3xx as a success (POST/redirect/GET).
- `info` verdict; `rule` is `null` on rows that are not findings.

## 1.0.0

Adversarial probes against an HTTP API running on the local machine, as a Claude Code plugin and a standalone CLI.

- Probe groups: malformed input, paths and query, raw parser errors, search (LIKE wildcards, injection), concurrent
  duplicate creates, oversized and never-ending bodies, database faults, authentication, ownership (IDOR), CSRF, durability.
- Stable finding ids (`<rule>:<probe>:<target>`), a rule registry with severities, and `--format json` with `schemaVersion: 1`
  and a summary of probes run, not run, skipped and suppressed.
- `http-attack.config.json`: per-route expectations (`public`, `bodyLimit`, `maxHeaderBytes`, `invalidUtf8`,
  `idempotentCreate`, `vary`, `contentType`) and suppressions with a mandatory reason.
- Exit codes: 0 no findings, 1 findings, 2 the run could not complete (crash, invalid argument, app down, no probe run, probe not run).
- Fault injection with `--fault-sqlite`, or with any shell command set as `faultCmd`/`faultRestore` in the config file (never on the command line).
- Bodies from files (`@body.json`) for Windows PowerShell 5.1, nested bodies (`--vary` JSON pointer), custom media types and
  custom authentication headers.
- Loopback hosts only. Zero runtime dependencies; Node 22.13 or newer.
