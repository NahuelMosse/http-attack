import { is2xx } from '../http.mjs';
import { wire } from '../body.mjs';

const snippet = (text) => text.replace(/\s+/g, ' ').slice(0, 120);

// Where a created item can be read back: the Location, else --item-path with the id from the JSON body.
export function itemUrlOf(res, { base, itemPath }) {
  if (res.headers.location) {
    try { const u = new URL(res.headers.location, base); return u.pathname + u.search; } catch { /* not a URL: fall through */ }
  }
  if (!itemPath) return null;
  try {
    const j = JSON.parse(res.text);
    const id = j?.id ?? j?.data?.id ?? j?.item?.id;
    return id === undefined ? null : itemPath.replace('{id}', encodeURIComponent(id));
  } catch { return null; }
}

// A stable label for an item URL: the id segment becomes {id}.
export const itemLabel = (url, template) => template ?? url.split('?')[0].replace(/[^/]+$/, '{id}');

// The id-less template of an item route, learned from a created item's Location when --item-path was not given.
export const inferTemplate = (url, res) => {
  const last = url.split('?')[0].split('/').pop();
  let id;
  try { id = JSON.parse(res.text)?.id; } catch { /* no JSON body */ }
  return last && (id === undefined || decodeURIComponent(last) === String(id)) ? url.split('?')[0].replace(/[^/]+$/, '{id}') : null;
};

// The legitimate create every other probe of this write depends on. { ok, res, item }.
export async function legitWrite(run, w) {
  const target = `${w.method} ${w.path}`;
  const spec = { group: 'auth', probe: 'legit-write', target, name: `${target} legitimate request` };
  const st = run.settings(w.method, w.path);
  const p = wire(w, st);
  if (p.error) { run.notRun(spec, p.error); return { ok: false }; }
  const res = await run.client.send(w.method, w.path, { body: p.text, type: p.type });
  if (await run.transportFault(res, spec, '2xx')) return { ok: false };
  if (res.s >= 400) {
    run.notRun(spec, `the legitimate request answered ${res.s} (${snippet(res.text)}): every other row of this write is unreliable until it succeeds`);
    return { ok: false, res };
  }
  run.pass(spec, res.s, '2xx');
  return { ok: true, res, item: itemUrlOf(res, { base: run.client.base, itemPath: run.itemPath }) };
}

// A group of probes that all depend on a legitimate write that failed.
export function notRunDependents(run, w, why) {
  const target = `${w.method} ${w.path}`;
  for (const [group, probe] of [['input', 'input-probes'], ['resources', 'resource-probes'], ['auth', 'access-probes'], ['csrf', 'csrf-probes']]) {
    if (group === 'csrf' && !run.opts.csrf) continue;
    run.notRun({ group, probe, target, name: `${target} ${probe}` }, `the legitimate request failed: ${why}`);
  }
}

const unauthenticated = async (run, spec, method, path, expected) => {
  const res = await run.client.send(method, path, { auth: 'none' });
  if (await run.transportFault(res, spec, expected)) return;
  if (is2xx(res.s)) run.fail('unauthenticated-access', spec, res.s, expected);
  else run.pass(spec, res.s, expected);
};

// Authentication and object ownership on the item a legitimate write created.
export async function accessProbes(run, w, legit) {
  const { client, opts } = run;
  const target = `${w.method} ${w.path}`;
  const spec = (probe, name, t = target) => ({ group: 'auth', probe, target: t, name });
  const st = run.settings(w.method, w.path);
  const label = legit.item ? itemLabel(legit.item, run.itemTemplate) : null;

  if (client.hasCredentials()) {
    if (st.public) run.skipped(spec('write-without-credentials', `${target} without credentials`), 'the route is configured public');
    else await unauthenticated(run, spec('write-without-credentials', `${target} without credentials`), w.method, w.path, '401 (or a redirect to login)');
    if (legit.item) await unauthenticated(run, spec('item-without-credentials', `GET ${label} without credentials`, `GET ${label}`), 'GET', legit.item, '401 (or a redirect to login)');
  } else if (!run.state.noCredentialsReported) {
    run.state.noCredentialsReported = true;
    run.notRun(spec('no-credentials', 'authentication probes', '*'),
      'no credentials were given (--header, --auth-env, --auth-header-name): the rows without credentials prove nothing. Suppress this row if the API is open by design');
  }

  if (!Object.keys(opts.otherHeaders).length) return;
  const idor = spec('idor', `${target} ownership`);
  if (!legit.item) { run.notRun(idor, 'the create answered no Location and --item-path was not given'); return; }
  const own = await client.send('GET', legit.item);
  if (!is2xx(own.s)) { run.notRun(idor, `user A cannot read the item it created (${own.s ?? own.err}): the ownership probes would prove nothing`); return; }
  const p = wire(w, st);
  const bCreate = await client.send(w.method, w.path, { body: p.text, type: p.type, auth: 'b' });
  const bItem = bCreate.s !== null && bCreate.s < 400 ? itemUrlOf(bCreate, { base: client.base, itemPath: run.itemPath }) : null;
  const bOwn = bItem ? await client.send('GET', bItem, { auth: 'b' }) : null;
  if (!bOwn || !is2xx(bOwn.s)) {
    run.notRun(idor, `user B's credentials cannot create and read their own item (create ${bCreate.s ?? bCreate.err}${bOwn ? `, read ${bOwn.s}` : ''}): a 401/403 below would be a bad token, not ownership`);
    return;
  }
  for (const m of ['GET', 'DELETE']) {
    const s = spec(`idor-${m.toLowerCase()}`, `${m} ${label} as another user (IDOR / BOLA)`, `${m} ${label}`);
    const r = await client.send(m, legit.item, { auth: 'b' });
    const expected = '404 (or 403)';
    if (await run.transportFault(r, s, expected)) continue;
    if (is2xx(r.s)) run.fail('idor', s, r.s, expected, "another user's credentials reach this object");
    else run.pass(s, r.s, expected);
  }
}

export async function readsWithoutCredentials(run) {
  const { client, opts } = run;
  if (!client.hasCredentials()) return;
  for (const r of opts.reads) {
    const spec = { group: 'auth', probe: 'read-without-credentials', target: `GET ${r.split('?')[0]}`, name: `GET ${r} without credentials` };
    if (run.settings('GET', r).public) run.skipped(spec, 'the route is configured public');
    else await unauthenticated(run, spec, 'GET', r, '401 (or a redirect to login)');
  }
}

// Cookie-authenticated apps: a write from another origin must be refused (CSRF). "Same site" includes another port.
export async function csrfProbes(run, w) {
  const { client } = run;
  const st = run.settings(w.method, w.path);
  const origins = [
    ['another-site', 'from another site', { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' }],
    ['another-port', 'from another port of the same host', { origin: `http://${client.base.hostname}:${client.port + 1}`, 'sec-fetch-site': 'same-site' }],
    ['null-origin', 'with Origin: null', { origin: 'null' }],
  ];
  for (const [tag, label, headers] of origins) {
    const target = `${w.method} ${w.path}`;
    const s = { group: 'csrf', probe: `origin-${tag}`, target, name: `${target} ${label}` };
    const p = wire(w, st);
    const r = await client.send(w.method, w.path, { body: p.text, type: p.type, headers });
    const expected = '403 (any 4xx): the Origin is not this app';
    if (await run.transportFault(r, s, expected)) continue;
    const toLogin = r.s >= 300 && r.s < 400 && /login|sign-?in|auth/i.test(r.headers.location ?? '');
    if (is2xx(r.s) || (r.s >= 300 && r.s < 400 && !toLogin)) run.fail('csrf', s, r.s, expected, r.s >= 300 ? `redirected to ${r.headers.location ?? '(no Location)'}: the write was accepted` : undefined);
    else if (r.s === 409) run.notRun(s, 'answered 409: the body was refused before the origin check, so the check was not reached');
    else run.pass(s, r.s, expected);
  }
}
