// Each review finding against a throwaway server that has exactly that behaviour. Every case asserts the finding where the
// behaviour is a defect, and its absence where the configuration or the server makes it correct.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALICE, BOB, ITEM, SKILL, attack, tempDir, writeTemp } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';

const withServer = async (quirks, fn) => {
  const s = await startQuirkServer(quirks);
  try { return await fn(s); } finally { await s.close(); }
};
const config = (dir, obj) => ['--config', writeTemp(dir, 'http-attack.config.json', JSON.stringify(obj))];

test('nested bodies: the varying field is found at any depth and --vary takes a JSON pointer', () => withServer({ nested: true }, async (s) => {
  const body = '{"item":{"name":"Ana","email":"ana@example.com"}}';
  const r = await attack(s.url, [...ALICE, '--write', `POST /items ${body}`, '--unique', `POST /items ${body}`]);
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
  assert.equal(r.byProbe('wrong-type-number-item.name')[0].verdict, 'pass', 'the wrong-type probe ran on the nested string field');
  assert.equal(r.row('ok:race-identical-creates:POST /items')?.verdict, 'pass', 'varied creates do not collide');
  const pointer = await attack(s.url, [...ALICE, '--write', `POST /items ${body}`, '--vary', '/item/email']);
  assert.equal(pointer.row('ok:legit-write:POST /items')?.verdict, 'pass');
  const bad = await attack(s.url, [...ALICE, '--write', `POST /items ${body}`, '--vary', '/item/nope']);
  assert.ok(bad.row('not-run:legit-write:POST /items'), 'a pointer that points nowhere is a NOT RUN row');
}));

test('a public read route is not a finding when the config says so', () => withServer({ publicRead: true }, async (s) => {
  const dir = tempDir();
  const flagged = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/catalog']);
  assert.ok(flagged.has('unauthenticated-access:read-without-credentials:GET /catalog'));
  const ok = await attack(s.url, [...ALICE, '--write', ITEM, '--read', '/catalog', ...config(dir, { routes: { '/catalog': { public: true, reason: 'a public catalogue' } } })]);
  assert.ok(!ok.has('unauthenticated-access:read-without-credentials:GET /catalog'));
  assert.equal(ok.row('skipped:read-without-credentials:GET /catalog')?.verdict, 'skipped');
}));

test('a redirect to login is a refusal; an open write is critical', async () => {
  await withServer({ loginRedirect: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.equal(r.row('ok:write-without-credentials:POST /items')?.verdict, 'pass');
    assert.equal(r.row('ok:item-without-credentials:GET /items/{id}')?.verdict, 'pass');
  });
  await withServer({ openWrite: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', 'POST /open {"a":"b"}']);
    assert.ok(r.has('unauthenticated-access:write-without-credentials:POST /open'));
  });
});

test('the header size probe follows maxHeaderBytes', () => withServer({ maxHeaderSize: 64 * 1024 }, async (s) => {
  const dir = tempDir();
  const flagged = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(flagged.has('parser-accepted:big-header:raw'), 'a 20 KB header is accepted by this server');
  const ok = await attack(s.url, [...ALICE, '--write', ITEM, ...config(dir, { maxHeaderBytes: 64 * 1024 })]);
  assert.equal(ok.row('ok:big-header:raw')?.verdict, 'pass');
}));

test('invalid UTF-8 replaced by design is accepted through invalidUtf8: replace', () => withServer({ utf8Replace: true }, async (s) => {
  const dir = tempDir();
  const flagged = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(flagged.has('accepted-invalid:invalid-utf8:POST /items'));
  const ok = await attack(s.url, [...ALICE, '--write', ITEM, ...config(dir, { routes: { '/items': { invalidUtf8: 'replace' } } })]);
  assert.equal(ok.row('ok:invalid-utf8:POST /items')?.verdict, 'pass');
}));

test('duplicates: distinct stored items are critical, one item behind several 2xx is an idempotent create', async () => {
  const unique = ['--unique', 'POST /things {"key":"k"}'];
  await withServer({ storedDuplicates: true }, async (s) => {
    const dir = tempDir();
    const r = await attack(s.url, [...ALICE, ...unique]);
    assert.ok(r.has('duplicates-stored:race-identical-creates:POST /things'));
    const flagged = await attack(s.url, [...ALICE, ...unique, ...config(dir, { routes: { '/things': { idempotentCreate: true, reason: 'ON CONFLICT DO NOTHING' } } })]);
    assert.ok(!flagged.has('duplicates-stored:race-identical-creates:POST /things'), 'idempotentCreate suppresses the check');
  });
  await withServer({ idempotentCreate: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, ...unique]);
    assert.ok(!r.has('duplicates-stored:race-identical-creates:POST /things'));
    assert.equal(r.row('ok:race-identical-creates:POST /things')?.verdict, 'pass');
  });
});

test('a custom auth header is stripped in the no-credentials rows once named', () => withServer({ authHeader: 'x-auth-token' }, async (s) => {
  const args = ['--header', 'X-Auth-Token: alice-token', '--write', ITEM];
  const without = await attack(s.url, args);
  assert.ok(without.row('not-run:no-credentials:*'), 'no recognised credential: a NOT RUN row, not silence');
  const named = await attack(s.url, [...args, '--auth-header-name', 'X-Auth-Token']);
  assert.equal(named.row('ok:write-without-credentials:POST /items')?.verdict, 'pass');
  assert.ok(!named.row('not-run:no-credentials:*'));
}));

test('the user content type is respected and "no Content-Type" really sends none', () => withServer({ jsonApi: true }, async (s) => {
  const body = '{"data":{"attributes":{"name":"Ana","email":"ana@example.com"}}}';
  const r = await attack(s.url, [...ALICE, '--content-type', 'application/vnd.api+json', '--write', `POST /items ${body}`]);
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
  assert.equal(r.row('ok:no-content-type:POST /items')?.verdict, 'pass');
  const posts = s.requests.filter((q) => q.method === 'POST' && q.url === '/items');
  assert.ok(posts.some((q) => q.headers['content-type'] === undefined), 'a request without a content-type was sent');
  assert.ok(posts.some((q) => q.headers['content-type'] === 'application/vnd.api+json'));
  assert.ok(r.has('media-type-strict:media-type-variant:POST /items'), 'the case variant of the custom media type is refused by this server');
}));

test('path parameters and any 5xx are checked, stack traces in every 5xx', () => withServer({ pathParam500: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM, '--item-path', '/items/{id}']);
  assert.ok(r.has('server-error:path-param-letters:GET /items/{id}'));
  assert.ok(r.has('stack-leak:path-param-letters:GET /items/{id}'), 'a stack in a non-fault 5xx is reported');
  const clean = await startQuirkServer({});
  try {
    const ok = await attack(clean.url, [...ALICE, '--write', ITEM, '--item-path', '/items/{id}']);
    assert.equal(ok.row('ok:path-param-letters:GET /items/{id}')?.verdict, 'pass');
  } finally { await clean.close(); }
}));

test('path parameters need an item route: without one the row is NOT RUN', () => withServer({ noLocation: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(r.row('not-run:path-params:GET {item}'));
}));

test('repo files are reported', () => withServer({ repoFile: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(r.has('file-served:file-served:GET /.git/config'));
}));

test('Rails-style 422 on a foreign Origin is a CSRF refusal', async () => {
  await withServer({ csrf422: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--header', 'Cookie: session=alice', '--write', ITEM, '--csrf']);
    assert.equal(r.row('ok:origin-another-site:POST /items')?.verdict, 'pass');
    assert.ok(!r.report.rows.some((x) => x.rule === 'csrf'));
  });
  await withServer({}, async (s) => {
    const r = await attack(s.url, [...ALICE, '--header', 'Cookie: session=alice', '--write', ITEM, '--csrf']);
    assert.ok(r.has('csrf:origin-another-site:POST /items'), 'a server that ignores Origin is vulnerable');
  });
});

test('faultCmd and faultRestore (config only): the fault is injected, the 5xx judged, the fault always restored', () => {
  const dir = tempDir();
  const flag = join(dir, 'fault.flag');
  const toggle = join(SKILL, '..', '..', 'test', 'helpers', 'toggle.mjs');
  return withServer({ faultFile: flag }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM,
      ...config(dir, { faultCmd: `node "${toggle}" on "${flag}"`, faultRestore: `node "${toggle}" off "${flag}"` })]);
    assert.equal(r.byProbe('database-fault')[0].verdict, 'pass');
    assert.ok(!existsSync(flag), 'the restore command ran');
    const broken = await attack(s.url, [...ALICE, '--write', ITEM,
      ...config(dir, { faultCmd: 'node -e "process.exit(3)"', faultRestore: `node "${toggle}" off "${flag}"` })]);
    assert.equal(broken.byProbe('database-fault')[0].verdict, 'not-run', 'a fault command that fails is NOT RUN');
  });
});

test('the fault probe is NOT RUN, and the command never runs, when no legitimate write succeeded', () => {
  const dir = tempDir();
  const flag = join(dir, 'fault.flag');
  const toggle = join(SKILL, '..', '..', 'test', 'helpers', 'toggle.mjs');
  return withServer({ faultFile: flag }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', 'POST /items {"nope":1}', ...config(dir, { faultCmd: `node "${toggle}" on "${flag}"` })]);
    assert.equal(r.byProbe('database-fault')[0].verdict, 'not-run');
    assert.match(r.byProbe('database-fault')[0].evidence, /no legitimate write succeeded/);
    assert.ok(!existsSync(flag), 'the fault command did not run');
  });
});

test('search: parsed rows, an envelope with a changing request id, and a control that matches nothing', async () => {
  await withServer({ likeWild: true, envelope: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM, '--search', '/items q']);
    assert.ok(r.has('wildcard-unescaped:percent:GET /items'));
    assert.ok(r.has('wildcard-unescaped:underscore:GET /items'));
    assert.ok(!r.findings.some((id) => id.startsWith('sql-injection')), 'an echoed term is not an injection');
  });
  await withServer({ envelope: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM, '--search', '/items q']);
    assert.equal(r.row('ok:percent:GET /items')?.verdict, 'pass');
    assert.equal(r.row('ok:injection-or-number:GET /items')?.verdict, 'pass');
  });
});

test('search without rows is NOT RUN, never a pass', () => withServer({}, async (s) => {
  const r = await attack(s.url, [...ALICE, '--search', '/items q']);
  assert.ok(r.row('not-run:percent:GET /items'));
}));

test('ownership: user B is validated before A is probed', async () => {
  await withServer({}, async (s) => {
    const bad = await attack(s.url, [...ALICE, '--other-header', 'Authorization: Bearer nobody', '--write', ITEM]);
    assert.ok(bad.row('not-run:idor:POST /items'), 'an invalid token for B must not read as "ownership holds"');
    const ok = await attack(s.url, [...ALICE, ...BOB, '--write', ITEM]);
    assert.equal(ok.row('ok:idor-get:GET /items/{id}')?.verdict, 'pass');
  });
});

test('the body that never ends is sent up to the configured limit, not a fixed 2 MB', () => withServer({ streamLimit: 3 << 20 }, async (s) => {
  const dir = tempDir();
  const guess = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(guess.has('no-body-limit:body-never-ends:POST /items'), 'with no limit given 2 MB is assumed and a 3 MB limit looks absent');
  const known = await attack(s.url, [...ALICE, '--write', ITEM, ...config(dir, { bodyLimit: 3 << 20 })]);
  assert.equal(known.row('ok:body-never-ends:POST /items')?.verdict, 'pass');
}));

test('1 MB probe pads the legitimate body, so a server with no limit is caught', async () => {
  await withServer({ noLimit: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.ok(r.has('no-body-limit:body-1mb:POST /items'));
  });
  await withServer({}, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.equal(r.row('ok:body-1mb:POST /items')?.verdict, 'pass');
  });
});

test('--format json does not change what is sent: a form body stays a form', () => withServer({}, async (s) => {
  await attack(s.url, [...ALICE, '--write', 'POST /items a=1&b=x@y.z']);
  const post = s.requests.find((q) => q.method === 'POST' && q.url === '/items');
  assert.equal(post.headers['content-type'], 'application/x-www-form-urlencoded');
}));

test('bodies load from a file and a failing legitimate create is NOT RUN for its dependents', () => withServer({}, async (s) => {
  const dir = tempDir();
  const file = writeTemp(dir, 'body.json', '{"name":"Ana","email":"ana@example.com"}');
  const ok = await attack(s.url, [...ALICE, '--write', `POST /items @${file}`]);
  assert.equal(ok.row('ok:legit-write:POST /items')?.verdict, 'pass');
  const refused = await attack(s.url, [...ALICE, '--write', 'POST /items {"nope":1}']);
  assert.ok(refused.row('not-run:legit-write:POST /items'));
  assert.ok(refused.row('not-run:input-probes:POST /items'), 'input probes are not reported as passed');
  assert.ok(refused.report.summary.notRun >= 2);
}));

test('the config file suppresses with a reason and reports the counts; unused ignores are listed', () => withServer({ repoFile: true }, async (s) => {
  const dir = tempDir();
  const ignore = [{ id: 'file-served:file-served:GET /.git/config', reason: 'the fixture serves it on purpose' }, { id: 'idor:*', reason: 'never matches' }];
  const r = await attack(s.url, [...ALICE, '--write', ITEM, ...config(dir, { ignore })]);
  assert.ok(!r.has('file-served:file-served:GET /.git/config'));
  assert.equal(r.row('file-served:file-served:GET /.git/config').verdict, 'suppressed');
  assert.equal(r.row('file-served:file-served:GET /.git/config').suppressedBy, 'the fixture serves it on purpose');
  assert.equal(r.report.summary.suppressed, 1);
  assert.deepEqual(r.report.unusedIgnores, ['idor:*']);
  assert.equal(r.report.schemaVersion, 1);
  for (const row of r.report.rows) assert.equal(typeof row.got, 'string');
  assert.ok(readFileSync(join(dir, 'http-attack.config.json'), 'utf8').includes('reason'));
}));
