// Each review finding against a throwaway server that has exactly that behaviour. Every case asserts the finding where the
// behaviour is a defect, and its absence where the configuration or the server makes it correct.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALICE, BOB, ITEM, ROOT, attack, runCli, tempDir, writeTemp } from './helpers/cli.mjs';
import { startQuirkServer } from './helpers/quirk-server.mjs';
import { startEarlyCloseServer } from './helpers/early-close-server.mjs';
import { granted } from '../skills/http-attack/scripts/lib/http.mjs';

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
  const toggle = join(ROOT, 'tests', 'helpers', 'toggle.mjs');
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

test('the fault command text never reaches the report', () => {
  const dir = tempDir();
  const flag = join(dir, 'fault.flag');
  const toggle = join(ROOT, 'tests', 'helpers', 'toggle.mjs');
  return withServer({ faultFile: flag }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM,
      ...config(dir, { faultCmd: `node "${toggle}" on "${flag}" --token=hunter2`, faultRestore: `node "${toggle}" off "${flag}"` })]);
    assert.equal(r.byProbe('database-fault')[0].verdict, 'pass');
    assert.doesNotMatch(r.stdout, /hunter2|toggle\.mjs/);
  });
});

test('the fault probe is NOT RUN, and the command never runs, when no legitimate write succeeded', () => {
  const dir = tempDir();
  const flag = join(dir, 'fault.flag');
  const toggle = join(ROOT, 'tests', 'helpers', 'toggle.mjs');
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

test('search whose parameter is required passes only when a row the run created is found by an exact search', async () => {
  await withServer({ requireQ: true }, async (s) => {
    const none = await attack(s.url, [...ALICE, '--search', '/items q']);
    assert.ok(none.row('not-run:percent:GET /items'), 'no row is known to exist: NOT RUN');
    assert.ok(!none.byProbe('percent').some((x) => x.verdict === 'pass'));
    const created = await attack(s.url, [...ALICE, '--write', ITEM, '--search', '/items q']);
    assert.equal(created.row('ok:percent:GET /items')?.verdict, 'pass');
    assert.equal(created.row('ok:injection-or-number:GET /items')?.verdict, 'pass');
  });
  await withServer({ requireQ: true, likeWild: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM, '--search', '/items q']);
    assert.ok(r.has('wildcard-unescaped:percent:GET /items'));
  });
});

test('ownership: user B is validated before A is probed', async () => {
  await withServer({}, async (s) => {
    const bad = await attack(s.url, [...ALICE, '--other-header', 'Authorization: Bearer nobody', '--write', ITEM]);
    assert.ok(bad.row('not-run:idor:POST /items'), 'an invalid token for B must not read as "ownership holds"');
    const ok = await attack(s.url, [...ALICE, ...BOB, '--write', ITEM]);
    assert.equal(ok.row('ok:idor-get:GET /items/{id}')?.verdict, 'pass');
  });
});

test('connection-dropped: a connection closed without a response, while the app stays up, is reported', async () => {
  await withServer({ dropBadJson: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.ok(r.has('connection-dropped:malformed-json:POST /items'));
    assert.ok(!r.has('process-died:malformed-json:POST /items'), 'the app answered afterwards');
  });
  await withServer({}, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM]);
    assert.ok(!r.findings.some((id) => id.startsWith('connection-dropped:')));
  });
});

test('fault-not-reported: a fault that a write answers with 2xx is a finding', () => {
  const dir = tempDir();
  const flag = join(dir, 'fault.flag');
  const toggle = join(ROOT, 'tests', 'helpers', 'toggle.mjs');
  return withServer({ faultFile: flag, faultIgnored: true }, async (s) => {
    const r = await attack(s.url, [...ALICE, '--write', ITEM,
      ...config(dir, { faultCmd: `node "${toggle}" on "${flag}"`, faultRestore: `node "${toggle}" off "${flag}"` })]);
    assert.ok(r.has('fault-not-reported:database-fault:POST /items'));
    assert.ok(!existsSync(flag), 'the restore command ran');
  });
});

test('the body that never ends is sent up to the configured limit; without one 2 MB is assumed',() => withServer({ streamLimit: 3 << 20 }, async (s) => {
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

test('a 1 MB body whose first attempt was stored but never answered is repeated with new values, so the missing limit is still found', () => withServer({ noLimit: true, dropBigAfterStoring: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--write', ITEM]);
  assert.ok(r.has('no-body-limit:body-1mb:POST /items'));
  assert.ok(!r.row('not-run:body-1mb:POST /items'));
}));

test('a 413 with Connection: close followed by a destroyed socket mid-upload passes the body limit, it is not a dropped connection', async () => {
  const s = await startEarlyCloseServer();
  try {
    for (let i = 0; i < 3; i++) {
      const r = await attack(s.url, [...ALICE, '--write', ITEM]);
      assert.equal(r.row('ok:body-1mb:POST /items')?.verdict, 'pass', `attempt ${i}`);
      assert.ok(!r.has('connection-dropped:body-1mb:POST /items'), `attempt ${i}`);
    }
  } finally { await s.close(); }
});

test('--format json does not change what is sent: a form body stays a form',() => withServer({}, async (s) => {
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

test('a body file with a byte order mark and CRLF line ends makes a legitimate write', () => withServer({}, async (s) => {
  const file = writeTemp(tempDir(), 'body.json', '﻿{\r\n  "name": "Ana",\r\n  "email": "ana@example.com"\r\n}\r\n');
  const r = await attack(s.url, [...ALICE, '--write', `POST /items @${file}`]);
  assert.equal(r.row('ok:legit-write:POST /items')?.verdict, 'pass');
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

test('"not-run:<probe>" suppresses the NOT RUN rows of that probe and no other', () => withServer({}, async (s) => {
  const ignore = [{ id: 'not-run:legit-write', reason: 'the create needs a field this run does not know' }];
  const r = await attack(s.url, [...ALICE, '--write', 'POST /items {"nope":1}', ...config(tempDir(), { ignore })]);
  assert.equal(r.row('not-run:legit-write:POST /items')?.verdict, 'suppressed');
  assert.equal(r.row('not-run:input-probes:POST /items')?.verdict, 'not-run');
}));

test('a redirect is a refusal only when a whole path segment of its Location names a login page', () => {
  const redirect = (location) => granted({ s: 302, headers: { location } });
  for (const login of ['/login', '/login?next=/authors/3', '/accounts/sign-in', 'https://idp.example/sso/start', '/auth/start', '/Login.html']) assert.equal(redirect(login), false, login);
  for (const open of ['/authors/3', '/lessons/4', '/processors', '/items/7', '/items?next=/login']) assert.equal(redirect(open), true, open);
  assert.equal(granted({ s: 302, headers: {} }), true, 'a redirect without a Location is not a login redirect');
  assert.equal(granted({ s: 401, headers: {} }), false);
});

test('credentials that are redirected to login make the legitimate write NOT RUN, not a created item', () => withServer({ loginRedirect: true }, async (s) => {
  const r = await attack(s.url, ['--header', 'Authorization: Bearer nobody', ...BOB, '--write', ITEM]);
  assert.match(r.row('not-run:legit-write:POST /items')?.evidence ?? '', /redirected to login.*credentials do not work/);
  assert.deepEqual(r.findings.filter((id) => /^(unauthenticated-access|idor):/.test(id)), [], 'no unauthenticated-access or idor finding is built on a redirect');
  assert.ok(r.report.summary.notRun >= 1);
}));

test("user B's credentials redirected to login on create make the ownership probes NOT RUN", () => withServer({ loginRedirect: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--other-header', 'Authorization: Bearer nobody', '--write', ITEM]);
  assert.ok(r.row('not-run:idor:POST /items'), 'B could not create: ownership was not tested');
  assert.ok(!r.findings.some((id) => id.startsWith('idor:')));
}));

test('--persist-save with credentials redirected to login saves nothing and exits 2', () => withServer({ loginRedirect: true }, async (s) => {
  const file = join(tempDir(), 'state.json');
  const r = await runCli([s.url, '--header', 'Authorization: Bearer nobody', '--write', ITEM, '--persist-save', file]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /redirected to login/);
  assert.equal(existsSync(file), false);
}));

test('CSRF probes send the cookie only: a Bearer token next to it would skip the check', () => withServer({ tokenSkipsCsrf: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--header', 'Cookie: session=alice', '--write', ITEM, '--csrf']);
  assert.ok(!r.findings.some((id) => id.startsWith('csrf:')), r.findings.join(', '));
  assert.equal(r.row('ok:origin-another-site:POST /items')?.verdict, 'pass');
  const named = await attack(s.url, ['--header', 'X-Token: alice', '--auth-header-name', 'X-Token', '--header', 'Cookie: session=alice', '--write', ITEM, '--csrf']);
  const sent = s.requests.filter((q) => q.headers.origin && q.headers['x-token'] !== undefined);
  assert.deepEqual(sent, [], 'a configured auth header is not sent with a CSRF probe');
  assert.equal(named.row('ok:origin-another-site:POST /items')?.verdict, 'pass');
}));

test('headers-missing is one finding per route template, whatever the ids in the paths', () => withServer({ uuid: true, bareItems: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, ...BOB, '--write', ITEM, '--common-headers', 'X-Request-Id']);
  const missing = r.findings.filter((id) => id.startsWith('headers-missing:'));
  assert.deepEqual(missing.sort(), ['headers-missing:common-headers:DELETE /items/{id}', 'headers-missing:common-headers:GET /items/{id}']);
  const again = await attack(s.url, [...ALICE, ...BOB, '--write', ITEM, '--common-headers', 'X-Request-Id']);
  assert.deepEqual(again.findings.filter((id) => id.startsWith('headers-missing:')).sort(), missing, 'the same ids on a second run with new UUIDs');
}));

test('a CSRF probe whose connection is reset once is repeated, not reported as a dropped connection', () => withServer({ resetFirstOrigin: true }, async (s) => {
  const r = await attack(s.url, [...ALICE, '--header', 'Cookie: session=alice', '--write', ITEM, '--csrf']);
  assert.ok(!r.report.rows.some((x) => x.rule === 'connection-dropped' && x.group === 'csrf'));
  assert.ok(r.byProbe('origin-another-port').length > 0 && r.byProbe('origin-another-port').every((x) => x.rule !== 'connection-dropped'));
}));
