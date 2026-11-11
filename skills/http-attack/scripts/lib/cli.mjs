import { HELP, parseArgs } from './args.mjs';
import { applyIgnores, checkIgnore, loadConfig, unusedRoutes } from './config.mjs';
import { UsageError } from './errors.mjs';
import { createClient } from './http.mjs';
import { EXIT } from './registry.mjs';
import { exitCode, renderJson, renderText, summarize } from './report.mjs';
import { Run } from './run.mjs';
import { accessProbes, csrfProbes, inferTemplate, legitWrite, notRunDependents, readsWithoutCredentials } from './probes/auth.mjs';
import { openapiProbe } from './openapi.mjs';
import { faultProbe } from './probes/fault.mjs';
import { ambientProbe, foreignHostProbe, foreignOriginProbes, legitRead } from './probes/origin.mjs';
import { formToJson } from './body.mjs';
import { malformedInput } from './probes/input.mjs';
import { parserProbes } from './probes/parser.mjs';
import { pathProbes } from './probes/paths.mjs';
import { checkPersistPath, persistSave, persistVerify } from './probes/persist.mjs';
import { raceProbe } from './probes/race.mjs';
import { resourceProbes } from './probes/resources.mjs';
import { searchProbes } from './probes/search.mjs';

const MAX_MISSING_LISTED = 10;

// `--ignore` ids get the same checks as the config file's entries; one already in the config keeps its own reason.
function cliIgnores(ids, own) {
  const entries = [...new Set(ids)].filter((id) => !own.some((e) => e.id === id)).map((id) => ({ id, reason: 'ignored with --ignore' }));
  entries.forEach((entry, i) => checkIgnore('--ignore', entry, i));
  return entries;
}

// Command-line options and the config file, merged: the command line wins, lists are concatenated.
function mergeOptions(opt, config) {
  const lower = (list) => list.map((h) => String(h).trim().toLowerCase()).filter(Boolean);
  const merged = {
    ...opt,
    writes: [...config.writes, ...opt.writes],
    uniques: [...config.uniques, ...opt.uniques],
    reads: [...config.reads, ...opt.reads],
    searches: [...config.searches, ...opt.searches],
    common: opt.common.length ? opt.common : lower(config.commonHeaders ?? []),
    rawExempt: opt.rawExempt ?? config.rawExempt,
    faultCmd: config.faultCmd,
    faultRestore: config.faultRestore,
    authHeaderNames: [...new Set([...lower(config.authHeaderNames ?? []), ...opt.authHeaderNames])],
    itemPath: opt.itemPath ?? config.itemPath,
    ignore: [...config.ignore, ...cliIgnores(opt.ignore, config.ignore)],
  };
  if (opt.json) for (const w of [...merged.writes, ...merged.uniques]) if (w.body && !/^\s*[{[]/.test(w.body)) w.body = formToJson(w.body);
  return merged;
}

async function runAll(run) {
  const { opts, client } = run;
  const first = await client.send('GET', '/', { common: false });
  if (first.s === null) throw new UsageError(`The app does not answer at ${client.base.origin}: ${first.err}`);
  run.itemPath = opts.itemPath;
  run.itemTemplate = opts.itemPath;
  run.state = {};

  const ready = [];
  const legits = new Map();
  for (const w of opts.writes) {
    const legit = await legitWrite(run, w);
    legits.set(w, legit);
    if (legit.ok && legit.item && !run.itemTemplate) run.itemTemplate = inferTemplate(legit.item, legit.res);
    if (legit.ok) ready.push(w);
    else notRunDependents(run, w, legit.res ? `answered ${legit.res.s}` : 'no usable answer');
  }
  // Before the probes that delete (IDOR) or store oversized rows, so the list still holds the legitimate rows.
  const createdBodies = ready.map((w) => w.body);
  for (const s of opts.searches) await searchProbes(run, s, createdBodies);
  for (const w of ready) await accessProbes(run, w, legits.get(w));
  await readsWithoutCredentials(run);
  for (const w of ready) await malformedInput(run, w);
  await pathProbes(run, { writes: opts.writes, itemTemplate: run.itemTemplate });
  await parserProbes(run, { writes: opts.writes });
  for (const w of ready) await resourceProbes(run, w);
  for (const u of opts.uniques) await raceProbe(run, u);
  if (opts.csrf) for (const w of ready) await csrfProbes(run, w);
  if (opts.noAmbient) {
    const responses = ready.map((w) => ({ method: w.method, path: w.path, res: legits.get(w).res }));
    for (const r of opts.reads) {
      const res = await client.send('GET', r);
      if (res.s !== null) responses.push({ method: 'GET', path: r, res });
    }
    ambientProbe(run, responses);
  }
  const origin = !opts.noAmbient && opts.originCheck === 'always';
  const host = opts.hostCheck || opts.strictHost;
  for (const w of ready) {
    if (origin) await foreignOriginProbes(run, w.method, w.path, w);
    if (host) await foreignHostProbe(run, w.method, w.path, w);
  }
  // A read is attacked only once a legitimate GET with credentials answers 2xx: a refusal would otherwise pass every row.
  if (origin || host) for (const r of opts.reads) {
    if (!(await legitRead(run, r))) continue;
    if (origin) await foreignOriginProbes(run, 'GET', r);
    if (host) await foreignHostProbe(run, 'GET', r);
  }
  if (opts.faultSqlite || opts.faultCmd) await faultProbe(run, ready[0]);
  if (opts.openapi) openapiProbe(run, opts.openapi);

  if (opts.common.length) {
    const wanted = `every response carries ${opts.common.join(', ')}`;
    const missing = client.missesByRoute(run.itemTemplate);
    for (const [route, { headers, statuses }] of [...missing].sort(([x], [y]) => x.localeCompare(y))) {
      const spec = { group: 'headers', probe: 'common-headers', target: route, name: `${route}: ${wanted}` };
      run.fail('headers-missing', spec, [...statuses].join(','), wanted, `answered ${[...statuses].join(', ')} without ${[...headers].join(', ')}`);
    }
    if (!missing.size) run.pass({ group: 'headers', probe: 'common-headers', target: 'responses', name: wanted }, 'all', wanted);
  }
}

function prepare(argv, { cwd, env }) {
  const parsed = parseArgs(argv, { cwd, env });
  if (parsed.help) return { parsed };
  const config = loadConfig(parsed.opt.config, { cwd, env, json: parsed.opt.json });
  const opts = mergeOptions(parsed.opt, config);
  const client = createClient(parsed.base, opts);
  return { parsed, config, opts, client, run: new Run({ client, opts, config }) };
}

async function execute({ parsed, config, opts, run }) {
  await runAll(run);
  const unusedIgnores = applyIgnores(run.rows, opts.ignore);
  const summary = summarize(run.rows);
  return { base: parsed.base.origin, rows: run.rows, summary, unusedIgnores, unusedRoutes: unusedRoutes(config) };
}

// The programmatic entry: takes the CLI arguments, returns the report (with its `exitCode`) instead of printing it.
// Usage problems reject with a UsageError; the help and the persistence steps belong to the command line.
export async function attack(argv, { cwd = process.cwd(), env = process.env } = {}) {
  const ctx = prepare(argv, { cwd, env });
  if (ctx.parsed.help) throw new UsageError('--help belongs to the command line.');
  if (ctx.opts.persistSave || ctx.opts.persistVerify) throw new UsageError('--persist-save and --persist-verify belong to the command line.');
  const report = await execute(ctx);
  return { ...report, exitCode: exitCode(report.summary) };
}

// Returns the exit code; output goes through `io` so tests can capture it.
export async function main(argv, io = {}) {
  const out = io.stdout ?? ((s) => process.stdout.write(s));
  const err = io.stderr ?? ((s) => process.stderr.write(s));
  const env = io.env ?? process.env;
  const cwd = io.cwd ?? process.cwd();
  try {
    const ctx = prepare(argv, { cwd, env });
    const { parsed, config, opts, client, run } = ctx;
    if (parsed.help) { out(`${HELP}
`); return EXIT.OK; }

    if (opts.persistSave || opts.persistVerify) {
      checkPersistPath(opts.persistSave ?? opts.persistVerify, config, cwd);
      run.itemPath = opts.itemPath;
      if (!(await client.alive())) throw new UsageError(`The app does not answer at ${parsed.base.origin}.`);
      const result = opts.persistSave ? await persistSave(run, opts.persistSave) : await persistVerify(run, opts.persistVerify);
      out(opts.format === 'json' ? `${JSON.stringify({ schemaVersion: 1, ok: result.ok, ...result.data }, null, 2)}
` : `${result.message}
`);
      return result.ok ? EXIT.OK : EXIT.FINDINGS;
    }

    const report = await execute(ctx);
    out(`${opts.format === 'json' ? renderJson(report) : renderText(report)}
`);
    return exitCode(report.summary);
  } catch (e) {
    if (e instanceof UsageError) err(`http-attack: ${e.message}
`);
    else err(`http-attack crashed: ${e?.stack ?? e}
`);
    return EXIT.ERROR;
  }
}
