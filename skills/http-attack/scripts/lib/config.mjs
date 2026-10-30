import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { UsageError } from './errors.mjs';
import { RULES } from './registry.mjs';
import { checkBody, readBodyFile, toPath } from './args.mjs';

export const DEFAULT_CONFIG_FILE = 'http-attack.config.json';

// Settings that apply to one route (or, at the top level, to every route).
const ROUTE_KEYS = ['public', 'bodyLimit', 'maxHeaderBytes', 'invalidUtf8', 'idempotentCreate', 'vary', 'contentType'];
const TOP_KEYS = [...ROUTE_KEYS, 'routes', 'ignore', 'commonHeaders', 'rawExempt', 'authHeaderNames', 'itemPath', 'persistIgnore',
  'writes', 'reads', 'searches', 'uniques'];

const fail = (file, msg) => { throw new UsageError(`${file}: ${msg}`); };

const checkRoute = (file, where, s) => {
  if (s === null || typeof s !== 'object' || Array.isArray(s)) fail(file, `${where} must be an object.`);
  for (const k of Object.keys(s)) if (!ROUTE_KEYS.includes(k)) fail(file, `${where}: unknown setting "${k}" (known: ${ROUTE_KEYS.join(', ')}).`);
  for (const k of ['public', 'idempotentCreate']) if (k in s && typeof s[k] !== 'boolean') fail(file, `${where}.${k} must be true or false.`);
  for (const k of ['bodyLimit', 'maxHeaderBytes']) if (k in s && !(Number.isInteger(s[k]) && s[k] > 0)) fail(file, `${where}.${k} must be a positive integer.`);
  if ('invalidUtf8' in s && !['reject', 'replace'].includes(s.invalidUtf8)) fail(file, `${where}.invalidUtf8 must be "reject" or "replace".`);
  for (const k of ['vary', 'contentType']) if (k in s && typeof s[k] !== 'string') fail(file, `${where}.${k} must be a string.`);
};

const requestOf = (file, where, r, cwd, env) => {
  if (!r || typeof r !== 'object' || typeof r.path !== 'string') fail(file, `${where} needs a "path".`);
  let body = r.body ?? '';
  if (typeof body === 'object') body = JSON.stringify(body);
  else if (typeof body === 'string' && body.startsWith('@')) body = readBodyFile(body.slice(1), cwd, `${file} ${where}`);
  else if (typeof body !== 'string') fail(file, `${where}.body must be an object, a string or "@file".`);
  checkBody(body, r.contentType, `${file} ${where}`);
  return { method: String(r.method ?? 'POST').toUpperCase(), path: toPath(r.path, env), body, contentType: r.contentType };
};

export function loadConfig(file, { cwd = process.cwd(), env = process.env } = {}) {
  const explicit = file !== undefined;
  const path = resolve(cwd, file ?? DEFAULT_CONFIG_FILE);
  const empty = { settings: {}, routes: {}, ignore: [], persistIgnore: [], writes: [], reads: [], searches: [], uniques: [], path: null };
  if (!explicit && !existsSync(path)) return empty;
  let raw;
  try { raw = readFileSync(path, 'utf8').replace(/^﻿/, ''); } catch (e) { fail(path, `cannot read the config file: ${e.code ?? e.message}`); }
  let json;
  try { json = JSON.parse(raw); } catch (e) { fail(path, `not valid JSON (${e.message}).\nreceived: ${raw.slice(0, 300)}`); }
  if (json === null || typeof json !== 'object' || Array.isArray(json)) fail(path, 'the top level must be an object.');
  for (const k of Object.keys(json)) if (!TOP_KEYS.includes(k)) fail(path, `unknown key "${k}" (known: ${TOP_KEYS.join(', ')}).`);
  checkRoute(path, 'top level', Object.fromEntries(Object.entries(json).filter(([k]) => ROUTE_KEYS.includes(k))));
  const routes = {};
  for (const [k, v] of Object.entries(json.routes ?? {})) {
    checkRoute(path, `routes["${k}"]`, v);
    const m = k.match(/^([A-Za-z]+) (.+)$/);
    routes[m ? `${m[1].toUpperCase()} ${toPath(m[2], env)}` : toPath(k, env)] = v;
  }
  const ignore = json.ignore ?? [];
  if (!Array.isArray(ignore)) fail(path, '"ignore" must be a list.');
  ignore.forEach((entry, i) => {
    if (typeof entry?.id !== 'string' || !entry.id.trim()) fail(path, `ignore[${i}] needs an "id" (a finding id, a rule name, or a prefix ending in *).`);
    if (typeof entry.reason !== 'string' || !entry.reason.trim()) fail(path, `ignore[${i}] ("${entry.id}") needs a non-empty "reason": a suppression without a reason is not accepted.`);
    const rule = entry.id.split(':')[0];
    if (!(rule in RULES) && !rule.endsWith('*')) fail(path, `ignore[${i}]: "${rule}" is not a rule (known: ${Object.keys(RULES).join(', ')}).`);
  });
  const list = (k) => { const v = json[k] ?? []; if (!Array.isArray(v)) fail(path, `"${k}" must be a list.`); return v; };
  const requests = (k) => list(k).map((r, i) => requestOf(path, `${k}[${i}]`, r, cwd, env));
  return {
    path,
    settings: Object.fromEntries(Object.entries(json).filter(([k]) => ROUTE_KEYS.includes(k))),
    routes,
    ignore,
    persistIgnore: list('persistIgnore'),
    commonHeaders: json.commonHeaders, rawExempt: json.rawExempt, authHeaderNames: json.authHeaderNames, itemPath: json.itemPath,
    writes: requests('writes'), uniques: requests('uniques'),
    reads: list('reads').map((r) => toPath(r, env)),
    searches: list('searches').map((s, i) => {
      if (typeof s?.path !== 'string' || typeof s.param !== 'string') fail(path, `searches[${i}] needs "path" and "param".`);
      return { path: toPath(s.path, env), param: s.param };
    }),
  };
}

// Settings for one route: top-level defaults, then the path, then "METHOD path"; flags given on the command line win over the defaults.
export const routeSettings = (config, flags, method, path) => {
  const key = path.split('?')[0];
  return {
    ...config.settings,
    ...(flags.bodyLimit ? { bodyLimit: flags.bodyLimit } : {}),
    ...(flags.vary ? { vary: flags.vary } : {}),
    ...config.routes[key],
    ...config.routes[`${method.toUpperCase()} ${key}`],
  };
};

const matches = (pattern, row) => pattern === row.id || pattern === row.rule
  || (pattern.endsWith('*') && row.id.startsWith(pattern.slice(0, -1)));

// A suppression keeps the row, marked with its reason; it no longer counts as a finding or a gap.
export function applyIgnores(rows, ignore) {
  const used = new Set();
  for (const row of rows) {
    if (row.verdict !== 'fail' && row.verdict !== 'not-run') continue;
    const hit = ignore.find((entry) => matches(entry.id, row));
    if (!hit) continue;
    used.add(hit);
    Object.assign(row, { was: row.verdict, verdict: 'suppressed', suppressedBy: hit.reason });
  }
  return ignore.filter((entry) => !used.has(entry));
}
