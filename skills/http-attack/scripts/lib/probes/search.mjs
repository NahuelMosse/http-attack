import { is2xx } from '../http.mjs';
import { nextCounter } from '../body.mjs';

const ENVELOPE_KEYS = ['data', 'items', 'results', 'rows', 'records', 'content', 'edges', 'hits'];

// The rows of a list response: a JSON array, or the array inside an envelope. null when the body is not a list.
export function rowsOf(text) {
  let v;
  try { v = JSON.parse(text); } catch { return null; }
  if (Array.isArray(v)) return v;
  if (v && typeof v === 'object') {
    const key = ENVELOPE_KEYS.find((k) => Array.isArray(v[k])) ?? Object.keys(v).find((k) => Array.isArray(v[k]));
    if (key) return v[key];
  }
  return null;
}
const keyOf = (row) => (row && typeof row === 'object' && row.id !== undefined ? `id:${JSON.stringify(row.id)}` : JSON.stringify(row));
const keys = (rows) => new Set(rows.map(keyOf));

const VALUES = [
  ['percent', '%'], ['underscore', '_'], ['quote-single', "'"], ['quote-double', '"'], ['backslash', '\\'],
  ['injection-or-number', "' OR 1=1 --"], ['injection-or-string', "%' OR '1'='1"],
];

// Free text taken literally: % and _ are LIKE wildcards; a quote that breaks the SQL is an injection.
// Rows are compared as parsed rows against a control search that matches nothing.
export async function searchProbes(run, { path: route, param }) {
  const { client } = run;
  const [p, q] = route.split('?');
  const target = `GET ${p}`;
  const spec = (probe, name) => ({ group: 'search', probe, target, name });
  const at = (v) => { const sp = new URLSearchParams(q ?? ''); if (v === null) sp.delete(param); else sp.set(param, v); const s = sp.toString(); return s ? `${p}?${s}` : p; };

  const all = await client.send('GET', at(null));
  const control = await client.send('GET', at(`zz-no-match-${nextCounter()}`));
  const allRows = is2xx(all.s) ? rowsOf(all.text) : null;
  const controlRows = is2xx(control.s) ? rowsOf(control.text) : null;
  let blocked = null;
  if (!allRows) blocked = `the unfiltered list did not answer a list of rows (${all.s ?? all.err})`;
  else if (allRows.length === 0) blocked = 'the unfiltered list is empty: create a row first, or the wildcard and injection checks prove nothing';
  else if (!controlRows) blocked = `a search that matches nothing did not answer a list (${control.s ?? control.err})`;
  else if (controlRows.length >= allRows.length) blocked = `the ${param} parameter does not filter: a search that matches nothing returned every row`;
  const allKeys = allRows ? keys(allRows) : new Set();

  for (const [tag, v] of VALUES) {
    const s = spec(tag, `GET ${at(v)}`);
    const expected = '200 with only the rows that contain that literal text (usually none)';
    const res = await client.send('GET', at(v));
    if (await run.transportFault({ ...res }, { ...s, hint: /'/.test(v) ? 'a quote breaks the query: SQL built by concatenation, or a driver that rejects the literal (to_tsquery): confirm' : undefined }, expected)) continue;
    if (blocked) { run.notRun(s, blocked); continue; }
    const rows = is2xx(res.s) ? rowsOf(res.text) : null;
    if (rows && (tag === 'percent' || tag === 'underscore') && keys(rows).size === allKeys.size && [...allKeys].every((k) => keys(rows).has(k))) {
      run.fail('wildcard-unescaped', s, res.s, expected, `${v} matched every row: it reached LIKE unescaped`);
    } else if (rows && tag.startsWith('injection') && rows.length > controlRows.length && [...allKeys].every((k) => keys(rows).has(k))) {
      run.fail('sql-injection', s, res.s, expected, 'the injected OR returned every row, a search that matches nothing returned none');
    } else run.pass(s, res.s, expected);
  }
}
