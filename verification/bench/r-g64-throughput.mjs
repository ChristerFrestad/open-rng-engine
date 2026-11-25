// r-g64 throughput micro-bench (design input for verification/r-g64-design.md; CTO 2026-11-25). Not evidence,
// not a gate, not run by npm test or check:ph0. It measures, on one machine, what one trusted helper process
// costs per public-call outcome for every distinct call shape in verification/k-tests-v1.1.json:
//   A  the engine's public call alone (integer / shuffle / sample / weightedPick from src/index.ts);
//   B  A + the collector's per-outcome shape check + an incremental sha256 over a fixed-width encoding;
//   C  B + writing the encoding in 64 KiB frames into a pipe read by a discarding child, with back-pressure
//      (the child stands in for a battery tool's stdin).
// and, for one shape, how the aggregate rate of stage C scales with P concurrent helper processes.
// Usage: node verification/bench/r-g64-throughput.mjs [--seconds S] [--scale 1,2,4,8] [--json out.json]
// The engine draws real entropy here (node:crypto randomFillSync through src/entropy); no outcome is kept.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { cpus, loadavg } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const E = await import(pathToFileURL(join(ROOT, 'src/index.ts')).href);
const { outcomeShapeError, windowWidth } = await import(pathToFileURL(join(ROOT, 'verification/harness/collector.mjs')).href);

// Digest of the engine build the outcomes come from: sha256 over the sorted (path, sha256(bytes)) list of src/.
export function srcDigest(root = ROOT) {
  const files = [];
  const walk = (d) => { for (const n of readdirSync(d).sort()) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else files.push(p); } };
  walk(join(root, 'src'));
  const h = createHash('sha256');
  for (const f of files) h.update(`${relative(root, f)}\0${createHash('sha256').update(readFileSync(f)).digest('hex')}\n`);
  return { files: files.length, sha256: h.digest('hex') };
}

const iota = (n) => Array.from({ length: n }, (_, i) => i);
function callFor(k) {
  const p = k.parameters || {};
  switch (k.primitive) {
    case 'randomInt': return () => E.integer(p.min, p.max);
    case 'shuffle': { const d = iota(p.n ?? 52); return () => E.shuffle(d); }
    case 'sample': return () => E.sample(p.n, p.k);
    case 'weightedPick': {
      const w = Array.isArray(p.weights) ? p.weights : p.strip === 'W-A' ? iota(64).map((i) => i + 1) : p.strip === 'W-B' ? iota(64).map((i) => i % 8) : null;
      if (!w) throw new Error(`no weights for ${k.id}`);
      return () => E.weightedPick(w);
    }
    default: throw new Error(`unknown primitive ${k.primitive}`);
  }
}
function shapeKey(k) {
  const p = k.parameters || {};
  const base = k.primitive === 'randomInt' ? `randomInt [${p.min},${p.max})` : k.primitive === 'shuffle' ? `shuffle n=${p.n ?? 52}`
    : k.primitive === 'sample' ? `sample n=${p.n} k=${p.k}` : `weightedPick ${Array.isArray(p.weights) ? `[${p.weights}]` : p.strip}`;
  return base;
}
// Distinct call shapes; tuple entries reuse the shape of their single call (a tuple of w is w calls).
export function shapes(tests) {
  const m = new Map();
  for (const k of tests) {
    const key = shapeKey(k);
    if (!m.has(key)) m.set(key, { key, k, entries: [] });
    m.get(key).entries.push({ id: k.id, family: k.family, w: windowWidth(k) });
  }
  return [...m.values()];
}
const valueBytes = (k) => (k.primitive === 'randomInt' && k.parameters.max > 2 ** 32 ? 8 : 4);
const CHUNK = 1 << 16;

function sink() {
  return spawn(process.execPath, ['-e', "process.stdin.on('data',()=>{});process.stdin.on('end',()=>process.exit(0))"], { stdio: ['pipe', 'ignore', 'inherit'] });
}
async function stage(shape, call, stageId, seconds) {
  const k = { ...shape.k, n_unit: 'public-call outcomes' }; // shape check per single call
  const per = valueBytes(k);
  const buf = Buffer.allocUnsafe(CHUNK); let off = 0;
  const h = createHash('sha256'); const child = stageId === 'C' ? sink() : null;
  const flush = async () => {
    const b = buf.subarray(0, off); h.update(b);
    if (child && !child.stdin.write(Buffer.from(b))) await new Promise((r) => child.stdin.once('drain', r));
    off = 0;
  };
  let n = 0, bad = 0;
  const t0 = process.hrtime.bigint(); const limit = BigInt(Math.round(seconds * 1e9));
  for (;;) {
    for (let i = 0; i < 256; i++) {
      const v = call(); n++;
      if (stageId === 'A') continue;
      if (outcomeShapeError(k, v) !== null) bad++;
      const vs = typeof v === 'number' ? [v] : v;
      if (off + vs.length * per > buf.length) await flush();
      for (const x of vs) { if (per === 8) { buf.writeUIntLE(x, off, 6); buf.writeUInt16LE(0, off + 6); } else buf.writeUInt32LE(x, off); off += per; }
    }
    if (process.hrtime.bigint() - t0 >= limit) break;
  }
  if (stageId !== 'A') { await flush(); h.digest(); }
  if (child) { child.stdin.end(); await new Promise((r) => child.on('exit', r)); }
  const ns = Number(process.hrtime.bigint() - t0) / n;
  if (bad) throw new Error(`${shape.key}: ${bad} outcomes failed the shape check`);
  return { n, nsPerCall: ns };
}

async function worker(key, seconds) {
  const sh = shapes(JSON.parse(readFileSync(join(ROOT, 'verification/k-tests-v1.1.json'), 'utf8')).tests).find((s) => s.key === key);
  const call = callFor(sh.k); for (let i = 0; i < 2000; i++) call();
  const r = await stage(sh, call, 'C', seconds);
  process.stdout.write(JSON.stringify(r));
}
function runWorker(key, seconds) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [SELF, '--worker', key, '--seconds', String(seconds)], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = ''; c.stdout.on('data', (d) => { out += d; });
    c.on('exit', (code) => (code === 0 ? res(JSON.parse(out)) : rej(new Error(`worker exit ${code}`))));
  });
}

const argv = process.argv.slice(2);
const opt = (name, d) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : d; };
const seconds = Number(opt('--seconds', '1.5'));
if (argv.includes('--worker')) { await worker(opt('--worker'), seconds); process.exit(0); }

const tests = JSON.parse(readFileSync(join(ROOT, 'verification/k-tests-v1.1.json'), 'utf8')).tests;
const meta = {
  bench: 'r-g64-throughput', bench_sha256: createHash('sha256').update(readFileSync(SELF)).digest('hex'), src: srcDigest(),
  node: process.version, cpu: cpus()[0]?.model, cpus: cpus().length, loadavg_start: loadavg(), started: new Date().toISOString(), seconds_per_stage: seconds,
};
console.log(`# ${meta.bench} sha256 ${meta.bench_sha256}; src ${meta.src.sha256} (${meta.src.files} files); node ${meta.node}; ${meta.cpus} x ${meta.cpu}; load ${meta.loadavg_start.map((x) => x.toFixed(2)).join(' ')}`);
const rows = [];
for (const sh of shapes(tests)) {
  const call = callFor(sh.k); for (let i = 0; i < 2000; i++) call();
  const r = { shape: sh.key, entries: sh.entries.length, tuple_entries: sh.entries.filter((e) => e.w > 1).map((e) => `${e.id} w=${e.w}`) };
  for (const s of ['A', 'B', 'C']) { const x = await stage(sh, call, s, seconds); r[s] = { n: x.n, ns: Math.round(x.nsPerCall) }; }
  r.hours_1e9_calls_one_core = +(r.C.ns * 1e9 / 1e9 / 3600).toFixed(3);
  rows.push(r);
  console.log(`${sh.key.padEnd(34)} A ${String(r.A.ns).padStart(8)} ns  B ${String(r.B.ns).padStart(8)} ns  C ${String(r.C.ns).padStart(8)} ns  10^9 calls ${String(r.hours_1e9_calls_one_core).padStart(8)} h/core  (${r.entries} entries)`);
}
const scaleShape = 'shuffle n=52';
const scale = [];
for (const P of opt('--scale', '1,2,4,8').split(',').map(Number)) {
  const t0 = process.hrtime.bigint();
  const rs = await Promise.all(Array.from({ length: P }, () => runWorker(scaleShape, seconds * 2)));
  const wall = Number(process.hrtime.bigint() - t0) / 1e9;
  const perSec = rs.reduce((a, r) => a + 1e9 / r.nsPerCall, 0);
  scale.push({ P, calls_per_sec_total: Math.round(perSec), per_helper_ns: rs.map((r) => Math.round(r.nsPerCall)), wall_s: +wall.toFixed(2) });
  console.log(`scale ${scaleShape} P=${P}: ${Math.round(perSec)} calls/s total; per-helper ns ${rs.map((r) => Math.round(r.nsPerCall)).join(' ')}`);
}
meta.loadavg_end = loadavg(); meta.finished = new Date().toISOString();
console.log(`# load end ${meta.loadavg_end.map((x) => x.toFixed(2)).join(' ')}`);
const out = opt('--json');
if (out) writeFileSync(out, JSON.stringify({ meta, rows, scale }, null, 2) + '\n');
