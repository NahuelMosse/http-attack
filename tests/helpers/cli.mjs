import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const SKILL = join(ROOT, 'skills', 'http-attack');
export const CLI = join(ROOT, 'bin', 'http-attack.mjs');
const FAST = ['--hang-ms', '600'];

// Runs the CLI as a child process (the test process hosts the servers, so its event loop must stay free).
export function runCli(args, { cwd, env, entry = CLI, timeoutMs = 180_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [entry, ...args], { cwd, env: { ...process.env, MSYS_NO_PATHCONV: '1', ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill(); reject(new Error(`CLI timed out: ${args.join(' ')}`)); }, timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, json: () => JSON.parse(stdout) });
    });
  });
}

export const ALICE = ['--header', 'Authorization: Bearer alice'];
export const BOB = ['--other-header', 'Authorization: Bearer bob'];
export const ITEM = 'POST /items {"name":"Ana","email":"ana@example.com"}';

// A JSON report run with short waits; returns the parsed report plus lookups by id.
export async function attack(url, args, options) {
  const r = await runCli([url, ...FAST, '--format', 'json', ...args], options);
  if (!r.stdout.trim().startsWith('{')) throw new Error(`no JSON report (exit ${r.code}): ${r.stderr}${r.stdout}`);
  const report = r.json();
  const row = (id) => report.rows.find((x) => x.id === id);
  const byProbe = (probe) => report.rows.filter((x) => x.probe === probe);
  return { ...r, report, row, byProbe, findings: report.findings, has: (id) => report.findings.includes(id) };
}

// Every directory made here is removed when the test process exits.
const made = [];
process.on('exit', () => { for (const d of made) { try { rmSync(d, { recursive: true, force: true }); } catch { /* still held open: the OS cleans the temp dir */ } } });
export const tempDir = () => { const d = mkdtempSync(join(tmpdir(), 'http-attack-test-')); made.push(d); return d; };
export const writeTemp = (dir, name, content) => { const p = join(dir, name); writeFileSync(p, content); return p; };
