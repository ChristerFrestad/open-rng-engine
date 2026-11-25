// R-G64 run plan (design §2-§4; HoQ addendum 1 A22 D22-1..3, D22-5, D22-7). Pure apart from reading files to
// hash them. M (outcomes, or tuples for tuple entries, per K entry) is a parameter of the plan, never a constant.
// One shared stream per call shape (Q2 B): entries with the same shape read the same stream; a tuple entry of
// width w reads consecutive non-overlapping w-call windows of it. A stream's parts are whole multiples of L,
// the lcm of its entries' widths, so no window ever straddles a part boundary.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { codecFor, shapeKey } from './stream-frames.mjs';
import { windowWidth } from './collector.mjs';

export const ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const PLAN_VERSION = 'r-g64-plan/1';
const sha = (b) => createHash('sha256').update(b).digest('hex');

// n_j = floor(U / N) + (j < U mod N), in units; every part is >= 1 unit.
export function partition(units, N) {
  if (!Number.isSafeInteger(units) || units < 1) throw new Error(`partition: units ${units}`);
  if (!Number.isSafeInteger(N) || N < 1 || N > units) throw new Error(`partition: N ${N} for ${units} units`);
  const q = Math.floor(units / N), r = units % N;
  return Array.from({ length: N }, (_, j) => q + (j < r ? 1 : 0));
}
const gcd = (a, b) => (b ? gcd(b, a % b) : a);
const lcm = (a, b) => (a / gcd(a, b)) * b;

// Engine-build digest: sha256 over the sorted (path, sha256(bytes)) list of src/ (same as the bench).
export function srcManifest(root = ROOT) {
  const files = [];
  const walk = (d) => { for (const n of readdirSync(d).sort()) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else files.push(p); } };
  walk(join(root, 'src'));
  const list = files.map((f) => [relative(root, f), sha(readFileSync(f))]);
  const h = createHash('sha256');
  for (const [p, s] of list) h.update(`${p}\0${s}\n`);
  return { files: list.length, sha256: h.digest('hex'), list };
}

// D22-7: everything the outcomes and their counting depend on. A checkpoint is reused only if all of it is equal.
export const BOUND_FILES = Object.freeze([
  'verification/k-tests-v1.1.json', 'verification/harness/collector.mjs', 'verification/harness/wave1-evidence.mjs',
  'verification/harness/evidence-entry.mjs', 'tools/ci/entropy-backstop.mjs',
  'verification/harness/stream-launcher.mjs', 'verification/harness/evidence-helper.mjs',
  'verification/harness/stream-frames.mjs', 'verification/harness/run-plan.mjs',
  'verification/statistic/wave1-statistic.mjs', 'verification/statistic/positional-statistic.mjs',
  'verification/harness/rc-decision.mjs',
]);
export function bindings(root = ROOT) {
  const files = {};
  for (const f of BOUND_FILES) files[f] = sha(readFileSync(join(root, f)));
  const src = srcManifest(root);
  return {
    files, node_version: process.version, node_binary_sha256: sha(readFileSync(realpathSync(process.execPath))),
    src_digest: src.sha256, src_files: src.files,
  };
}
export function reuseMismatches(prev, cur) {
  const out = [];
  if (!prev || !cur) return ['missing bindings'];
  for (const f of new Set([...Object.keys(prev.files || {}), ...Object.keys(cur.files || {})])) {
    if ((prev.files || {})[f] !== (cur.files || {})[f]) out.push(`sha256 of ${f}`);
  }
  for (const k of ['node_version', 'node_binary_sha256', 'src_digest', 'src_files']) if (prev[k] !== cur[k]) out.push(k);
  return out;
}

export function loadKTests(root = ROOT) { return JSON.parse(readFileSync(join(root, 'verification/k-tests-v1.1.json'), 'utf8')).tests; }

// M: { [entryId]: units } for exactly the entries in this run. N: parts per stream (or { [streamId]: N }).
// prefix names this run's streams; run 2 uses its own prefix, so it never shares a stream with run 1.
export function buildPlan({ runId, M, N, prefix = 'S', kTests = loadKTests(), countingRule = null, extra = {} }) {
  if (typeof runId !== 'string' || !runId) throw new Error('plan: runId required');
  if (!M || typeof M !== 'object') throw new Error('plan: M per entry required (a parameter, never hard-coded)');
  const byId = new Map(kTests.map((k) => [k.id, k]));
  const streams = new Map();
  for (const id of Object.keys(M)) {
    const k = byId.get(id);
    if (!k) throw new Error(`plan: ${id} is not a K entry`);
    if (!Number.isSafeInteger(M[id]) || M[id] < 1) throw new Error(`plan: M for ${id} is ${M[id]}`);
    const key = shapeKey(k);
    if (!streams.has(key)) streams.set(key, { shape: key, rep: id, entries: [] });
    streams.get(key).entries.push({ id, w: windowWidth(k), M: M[id] });
  }
  const order = [...streams.values()].sort((a, b) => kTests.findIndex((k) => k.id === a.rep) - kTests.findIndex((k) => k.id === b.rep));
  const out = order.map((s, i) => {
    const id = `${prefix}${String(i + 1).padStart(2, '0')}`;
    const L = s.entries.reduce((a, e) => lcm(a, e.w), 1);
    const calls = Math.max(...s.entries.map((e) => e.M * e.w));
    const units = Math.ceil(calls / L);
    const n = typeof N === 'object' ? N[id] : N;
    const parts = partition(units, Math.min(n, units)).map((u) => u * L);
    const codec = codecFor(byId.get(s.rep));
    return { id, shape: s.shape, rep: s.rep, L, calls: units * L, parts, outcome_bytes: codec.bytes, entries: s.entries };
  });
  const streamMap = {};
  for (const s of out) for (const e of s.entries) streamMap[e.id] = s.id;
  return { v: PLAN_VERSION, run_id: runId, counting_rule: countingRule, M_per_entry: { ...M }, stream_map: streamMap, streams: out, ...extra };
}
export const planDigest = (plan) => sha(JSON.stringify(plan));
