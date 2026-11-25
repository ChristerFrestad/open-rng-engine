// r-g64 A25 overhead bench under HoQ A30 (A29-1 method ruling): paired ABBA repeats, per-pair load guard, every
// attempt kept in the JSON. The timed child is verification/bench/r-g64-a25-stageA.mjs --child (unchanged), so the
// per-child method (warm-up, ~20 ms batches, first-walk burn excluded, median_ns over batches) is the stage A one.
// Not evidence, not a gate, not run by npm test. One bench at a time.
// Pre-registration: --prereg <file.json> must name { N, k, guard, backoff_s, seconds, bench_sha256, child_sha256,
// method_sha256, backstop_sha256 } and every field must match this run, or the bench refuses to start.
// Usage: node verification/bench/r-g64-a25-a30.mjs --prereg P.json --json out.json [--shapes "<key>|<key>"]
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { cpus, loadavg } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { A30, runEntry, overallVerdict, shapeKeys } from './a30-method.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const CHILD = join(ROOT, 'verification/bench/r-g64-a25-stageA.mjs');
const METHOD = join(ROOT, 'verification/bench/a30-method.mjs');
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const argv = process.argv.slice(2);
const opt = (name, d) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : d; };
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');

const preregPath = opt('--prereg'); const out = opt('--json');
if (!preregPath || !out) { console.error('usage: --prereg P.json --json out.json'); process.exit(2); }
const P = JSON.parse(readFileSync(preregPath, 'utf8'));
const B = await import(new URL('../harness/run-plan.mjs', import.meta.url).href);
const live = { k: B.HELPER_PLAN.sample_k, guard: A30.GUARD_LOAD1, bench_sha256: sha(SELF), child_sha256: sha(CHILD), method_sha256: sha(METHOD), backstop_sha256: sha(BACKSTOP) };
for (const [f, v] of Object.entries(live)) if (P[f] !== v) { console.error(`prereg ${f} = ${P[f]}, this run has ${v}: refusing`); process.exit(3); }
for (const f of ['N', 'backoff_s', 'seconds']) if (!Number.isFinite(P[f])) { console.error(`prereg ${f} missing`); process.exit(3); }

const keys = shapeKeys(JSON.parse(readFileSync(join(ROOT, 'verification/k-tests-v1.1.json'), 'utf8')).tests);
const only = opt('--shapes'); const run = only ? keys.filter((k) => only.split('|').includes(k)) : keys;
if (!run.length) { console.error('no shapes'); process.exit(2); }

const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
const meta = { bench: 'r-g64-a25-a30', method: 'HoQ A30', prereg: P, prereg_sha256: sha(preregPath), head, node: process.version, cpus: cpus().length, cpu: cpus()[0]?.model, loadavg_start: loadavg(), started: new Date().toISOString(), shapes: run };
console.log(`# ${meta.bench} N=${P.N} k=${P.k} guard ${P.guard} backoff ${P.backoff_s}s seconds ${P.seconds}; bench ${live.bench_sha256}; child ${live.child_sha256}; method ${live.method_sha256}; backstop ${live.backstop_sha256}; head ${head}; prereg ${meta.prereg_sha256}`);
const child = (which, { key, burn }) => {
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.ENTROPY_BACKSTOP_HELPER; if (which === 'a25') env.ENTROPY_BACKSTOP_HELPER = 'a25';
  const r = spawnSync(process.execPath, [...(which === 'a25' ? ['--import', BACKSTOP] : []), CHILD, '--child', key, '--seconds', String(P.seconds), '--burn', String(burn ?? 0)], { cwd: ROOT, env, encoding: 'utf8', timeout: 120000 });
  if (r.status !== 0) throw new Error(`${key} ${which}: exit ${r.status} ${r.stderr.slice(0, 400)}`);
  const j = JSON.parse(r.stdout);
  if (which === 'a25' && j.helper?.state?.sample_k !== P.k) throw new Error(`${key}: helper k ${j.helper?.state?.sample_k} != prereg ${P.k}`);
  return j;
};
const entries = [];
const pct = (f) => (f === null ? '  n/a' : `${(f * 100).toFixed(1)}%`);
for (const key of run) {
  const e = await runEntry({ key, N: P.N, guard: P.guard, backoffMs: P.backoff_s * 1000, sampleLoad: () => loadavg()[0], runChild: child, sleep: (ms) => new Promise((r) => setTimeout(r, ms)) });
  entries.push(e);
  writeFileSync(out, JSON.stringify({ meta, entries }, null, 2) + '\n'); // after every entry: nothing is lost if stopped
  const voids = e.pairs.filter((p) => p.void).length;
  console.log(`${key.padEnd(30)} ${e.verdict.padEnd(12)} median ${pct(e.median)} max ${pct(e.max)} above10 ${e.above}/${e.valid} | valid ${e.valid} void ${voids} | pairs ${e.pairs.filter((p) => !p.void).map((p) => (p.overhead * 100).toFixed(1)).join('/')}%`);
}
meta.verdict = overallVerdict(entries); meta.loadavg_end = loadavg(); meta.finished = new Date().toISOString();
meta.max_median = Math.max(...entries.filter((e) => e.median !== null).map((e) => e.median));
writeFileSync(out, JSON.stringify({ meta, entries }, null, 2) + '\n');
console.log(`# A30 verdict ${meta.verdict}; max entry median ${pct(meta.max_median)}; entries FAIL: ${entries.filter((e) => e.verdict === 'FAIL').map((e) => e.key).join(', ') || 'none'}; INCONCLUSIVE: ${entries.filter((e) => e.verdict === 'INCONCLUSIVE').map((e) => e.key).join(', ') || 'none'}; load end ${meta.loadavg_end.map((x) => x.toFixed(2)).join(' ')}`);
