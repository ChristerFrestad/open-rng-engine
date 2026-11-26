#!/usr/bin/env node
// A25-2 (design v1 §1): trace the evidence helper's module closure and pin it in verification/harness/helper-closure.json.
// For every K entry rep it starts verification/harness/evidence-helper.mjs once (2 calls) under the real preload in
// helper mode with a broad manifest (every file under src/, verification/, tools/ci/), and a tracer (a load hook the
// tracer registers before the preload's, so it sees every module the helper loads) records each file URL under the
// tree. The union, as sorted posix relpaths, is the closure. Light: 24 sequential single-process runs of 2 calls.
// Usage: node tools/ci/a25-trace-closure.mjs [--write]   (prints the closure; --write pins it)
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildManifest } from './a25-manifest.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
const OUT = join(ROOT, 'verification/harness/helper-closure.json');
const walk = (a) => readdirSync(a, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(a, e.name)) : [join(a, e.name)]));
const broad = ['src', 'verification', 'tools/ci'].flatMap((d) => walk(join(ROOT, d))).map((f) => f.slice(ROOT.length + 1));
const tmp = mkdtempSync(join(tmpdir(), 'a25-trace-'));
try {
  const { bytes, sha256 } = buildManifest(ROOT, broad);
  const manifestPath = join(tmp, 'manifest.json');
  writeFileSync(manifestPath, bytes);
  const { helperSpawnEnv } = await import(pathToFileURL(join(ROOT, 'verification/harness/stream-launcher.mjs')).href);
  const { loadKTests } = await import(pathToFileURL(join(ROOT, 'verification/harness/run-plan.mjs')).href);
  const log = join(tmp, 'loaded.txt');
  const tracer = join(tmp, 'tracer.mjs');
  writeFileSync(tracer, `import { registerHooks } from 'node:module';\nimport { appendFileSync } from 'node:fs';\nregisterHooks({ load(url, c, next) { if (url.startsWith('file:')) appendFileSync(${JSON.stringify(log)}, url + '\\n'); return next(url, c); } });\n`);
  const seen = new Set();
  for (const k of loadKTests(ROOT)) {
    const env = helperSpawnEnv(process.env, { token: 'grant-0@0#trace', manifestPath, manifestSha256: sha256 });
    const r = spawnSync(process.execPath, ['--import', tracer, '--import', join(ROOT, 'tools/ci/entropy-backstop.mjs'), join(ROOT, 'verification/harness/evidence-helper.mjs'), '--run', 'trace', '--stream', 'trace', '--rep', k.id, '--j', '0', '--calls', '2'], { cwd: ROOT, env, encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe', 'pipe'], timeout: 60000 });
    if (r.status !== 0) throw new Error(`trace: ${k.id} exited ${r.status}: ${r.stderr}`);
    seen.add(k.id);
  }
  const rel = [...new Set(readFileSync(log, 'utf8').split('\n').filter(Boolean))]
    .map((u) => fileURLToPath(u)).filter((p) => p.startsWith(ROOT + '/')).map((p) => p.slice(ROOT.length + 1))
    .filter((p) => p !== 'tools/ci/entropy-backstop.mjs' && p !== 'tools/ci/a25-manifest.mjs' && p !== 'tools/ci/a25-lockdown.mjs') // loaded before any hook; bound via BOUND_FILES + the proof
    .sort();
  const body = JSON.stringify({ version: 1, traced_reps: [...seen].sort(), node: process.version, relpaths: rel }, null, 1) + '\n';
  if (process.argv.includes('--write')) writeFileSync(OUT, body);
  process.stdout.write(body);
} finally { rmSync(tmp, { recursive: true, force: true }); }
