import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { ALICE, BOB, SKILL, runCli, tempDir } from './cli.mjs';

// The one command both fixtures are attacked with: a fixed API must report nothing, the vulnerable one a known set.
export const FIXTURE_ARGS = (db) => [
  ...ALICE, ...BOB, '--header', 'Cookie: session=alice',
  '--write', 'POST /items {"name":"Ana","email":"ana@example.com"}',
  '--write', 'POST /notes {"title":"Hello"}',
  '--read', '/items?limit=10', '--search', '/items q',
  '--unique', 'POST /items {"name":"Uno","email":"uno@example.com"}',
  '--unique', 'POST /notes {"title":"Dup"}',
  '--common-headers', 'X-Request-Id, Cache-Control', '--body-limit', '65536', '--csrf', '--hang-ms', '1500',
  '--fault-sqlite', db, '--format', 'json',
];

export async function startFixture(kind, db) {
  const child = spawn(process.execPath, [join(SKILL, 'fixtures', `${kind}-server.mjs`), '0', db], { stdio: ['ignore', 'pipe', 'pipe'] });
  const port = await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (d) => { out += d; const m = out.match(/ on (\d+)/); if (m) resolve(Number(m[1])); });
    child.on('exit', (code) => reject(new Error(`${kind} fixture exited ${code}`)));
    setTimeout(() => reject(new Error(`${kind} fixture did not start`)), 60_000);
  });
  return { url: `http://127.0.0.1:${port}`, stop: () => child.kill() };
}

// Attacks one fresh fixture; returns the exit code, the sorted finding ids and the report.
export async function attackFixture(kind) {
  const db = join(tempDir(), `${kind}.db`);
  const fixture = await startFixture(kind, db);
  try {
    const r = await runCli([fixture.url, ...FIXTURE_ARGS(db)], { env: { MSYS_NO_PATHCONV: '1' } });
    const report = r.json();
    return { code: r.code, ids: [...report.findings].sort(), report };
  } finally { fixture.stop(); }
}
