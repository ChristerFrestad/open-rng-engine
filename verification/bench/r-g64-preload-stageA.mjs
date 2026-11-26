// r-g64 bench stage A WITH the entropy-backstop preload (CTO option 1, 2026-11-25). Not evidence, not a gate,
// not run by npm test or check:ph0. One helper at a time, never in parallel. For every distinct call shape in
// verification/k-tests-v1.1.json it runs one child plain and one child under `--import tools/ci/entropy-backstop.mjs`
// and times the engine's public call alone (stage A) in batches after a warm-up, so startup is not in the figure.
// Per call: median and p95 over batches. Factor = median with preload / median without. Stops if load1 > 4.
// Usage: node verification/bench/r-g64-preload-stageA.mjs [--seconds S] [--json out.json]
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { cpus, loadavg } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const argv = process.argv.slice(2);
const opt = (name, d) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : d; };
const tests = JSON.parse(readFileSync(join(ROOT, 'verification/k-tests-v1.1.json'), 'utf8')).tests;
const iota = (n) => Array.from({ length: n }, (_, i) => i);
function shapeKey(k) {
  const p = k.parameters || {};
  return k.primitive === 'randomInt' ? `randomInt [${p.min},${p.max})` : k.primitive === 'shuffle' ? `shuffle n=${p.n ?? 52}`
    : k.primitive === 'sample' ? `sample n=${p.n} k=${p.k}` : `weightedPick ${Array.isArray(p.weights) ? `[${p.weights}]` : p.strip}`;
}
function shapes() { const m = new Map(); for (const k of tests) { const key = shapeKey(k); if (!m.has(key)) m.set(key, { key, k, entries: [] }); m.get(key).entries.push(k.id); } return [...m.values()]; }

if (argv.includes('--child')) {
  const t0 = process.hrtime.bigint();
  const E = await import(pathToFileURL(join(ROOT, 'src/index.ts')).href);
  const sh = shapes().find((s) => s.key === opt('--child'));
  const p = sh.k.parameters || {};
  let call;
  switch (sh.k.primitive) {
    case 'randomInt': call = () => E.integer(p.min, p.max); break;
    case 'shuffle': { const d = iota(p.n ?? 52); call = () => E.shuffle(d); break; }
    case 'sample': call = () => E.sample(p.n, p.k); break;
    default: { const w = Array.isArray(p.weights) ? p.weights : p.strip === 'W-A' ? iota(64).map((i) => i + 1) : iota(64).map((i) => i % 8); call = () => E.weightedPick(w); }
  }
  const startup_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  // warm-up, then size a batch to about 20 ms
  let b = 1; for (;;) { const s = process.hrtime.bigint(); for (let i = 0; i < b; i++) call(); const ns = Number(process.hrtime.bigint() - s); if (ns > 2e7 || b > 1e6) break; b *= 2; }
  const per = [], limit = Number(opt('--seconds', '4')) * 1e9; const tA = process.hrtime.bigint();
  while (Number(process.hrtime.bigint() - tA) < limit && per.length < 400) { const s = process.hrtime.bigint(); for (let i = 0; i < b; i++) call(); per.push(Number(process.hrtime.bigint() - s) / b); }
  per.sort((x, y) => x - y);
  const q = (f) => per[Math.min(per.length - 1, Math.floor(f * per.length))];
  process.stdout.write(JSON.stringify({ batch: b, batches: per.length, median_ns: q(0.5), p95_ns: q(0.95), startup_ms }));
  process.exit(0);
}

const sha = (b) => createHash('sha256').update(b).digest('hex');
function srcDigest() { const files = []; const walk = (d) => { for (const n of readdirSync(d).sort()) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else files.push(p); } }; walk(join(ROOT, 'src')); const h = createHash('sha256'); for (const f of files) h.update(`${relative(ROOT, f)}\0${sha(readFileSync(f))}\n`); return h.digest('hex'); }
const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
const seconds = opt('--seconds', '4');
const meta = { bench: 'r-g64-preload-stageA', mode: 'WITH preload vs without', bench_sha256: sha(readFileSync(SELF)), backstop_sha256: sha(readFileSync(BACKSTOP)), head, src: srcDigest(), node: process.version, cpu: cpus()[0]?.model, cpus: cpus().length, loadavg_start: loadavg(), started: new Date().toISOString(), seconds_per_child: Number(seconds) };
console.log(`# ${meta.bench} WITH preload; sha256 ${meta.bench_sha256}; head ${head}; src ${meta.src}; backstop ${meta.backstop_sha256}; node ${meta.node}; ${meta.cpus} x ${meta.cpu}; load ${meta.loadavg_start.map((x) => x.toFixed(2)).join(' ')}`);
const run = (key, pre) => {
  const env = { ...process.env }; delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, [...(pre ? ['--import', BACKSTOP] : []), SELF, '--child', key, '--seconds', seconds], { cwd: ROOT, env, encoding: 'utf8', timeout: 120000 });
  if (r.status !== 0) throw new Error(`${key} ${pre ? 'preload' : 'plain'}: exit ${r.status} ${r.stderr.slice(0, 400)}`);
  return JSON.parse(r.stdout);
};
const rows = [];
let stopped = null;
for (const sh of shapes()) {
  if (loadavg()[0] > 4) { stopped = `load ${loadavg()[0].toFixed(2)} > 4 before ${sh.key}`; break; }
  const plain = run(sh.key, false), pre = run(sh.key, true);
  const r = { shape: sh.key, entries: sh.entries.length, plain, preload: pre, factor_median: +(pre.median_ns / plain.median_ns).toFixed(2), factor_p95: +(pre.p95_ns / plain.p95_ns).toFixed(2), load1: +loadavg()[0].toFixed(2) };
  rows.push(r);
  console.log(`${sh.key.padEnd(30)} plain med ${plain.median_ns.toFixed(0).padStart(9)} p95 ${plain.p95_ns.toFixed(0).padStart(9)} ns | WITH preload med ${pre.median_ns.toFixed(0).padStart(9)} p95 ${pre.p95_ns.toFixed(0).padStart(9)} ns | factor ${r.factor_median}x (p95 ${r.factor_p95}x) | startup ${plain.startup_ms.toFixed(0)}/${pre.startup_ms.toFixed(0)} ms | load ${r.load1}`);
}
meta.loadavg_end = loadavg(); meta.finished = new Date().toISOString(); meta.stopped = stopped;
console.log(`# load end ${meta.loadavg_end.map((x) => x.toFixed(2)).join(' ')}${stopped ? `; STOPPED: ${stopped}` : ''}`);
const out = opt('--json'); if (out) writeFileSync(out, JSON.stringify({ meta, rows }, null, 2) + '\n');
