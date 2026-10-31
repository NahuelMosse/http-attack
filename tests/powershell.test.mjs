import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { ALICE, BOB, CLI, tempDir } from './helpers/cli.mjs';
import { startFixture } from './helpers/fixtures.mjs';

// Windows PowerShell 5.1 writes files in its own encoding and quotes native arguments its own way.
const skip = process.platform !== 'win32' && 'Windows PowerShell exists only on Windows';

// Runs a script in Windows PowerShell; -EncodedCommand passes it without a second layer of quoting.
const powershell = (script) => new Promise((resolve, reject) => {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]);
  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  child.on('error', reject);
  child.on('close', (code) => resolve({ code, stdout, stderr }));
});

const quote = (s) => `'${s.replaceAll("'", "''")}'`;

test('Windows PowerShell 5.1: a body file written with Set-Content makes a legitimate write', { skip, timeout: 180_000 }, async () => {
  const dir = tempDir();
  const fixture = await startFixture('fixed', join(dir, 'app.db'));
  try {
    const body = join(dir, 'body.json');
    const args = [CLI, fixture.url, ...ALICE, ...BOB, '--write', `POST /items @${body}`, '--format', 'json'];
    const r = await powershell([
      `Set-Content -Path ${quote(body)} -Value '{"name":"Ana","email":"ana@example.com"}'`,
      `node ${args.map(quote).join(' ')}`,
      'exit $LASTEXITCODE',
    ].join('\n'));
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const report = JSON.parse(r.stdout);
    assert.ok(report.rows.some((row) => row.id === 'ok:legit-write:POST /items'), r.stdout);
  } finally { fixture.stop(); }
});
