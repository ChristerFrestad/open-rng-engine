// R-G64 test fixture: a deterministic stand-in for verification/harness/evidence-helper.mjs. Outcome number t of
// a stream (global call index, so any partition of the same stream gives the same sequence) is derived from
// sha256(seed:t). It writes the real frame format and the real H/T fields; --fault makes one integrity defect.
// Never used for evidence: the launcher's real path spawns only the real helper.
import { createHash } from 'node:crypto';
import { readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const F = await import(new URL('../../verification/harness/stream-frames.mjs', import.meta.url).href);
const P = await import(new URL('../../verification/harness/run-plan.mjs', import.meta.url).href);
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i < 0 ? d : process.argv[i + 1]; };
const runId = arg('run'), stream = arg('stream'), rep = arg('rep'), j = Number(arg('j')), calls = Number(arg('calls')), off = Number(arg('off')), seed = arg('seed', 's');
const fault = arg('fault', 'none');
// A25-1: the real preload reads the grant token from its env; under npm test this child's preload is not in helper
// mode and drops that env, so the fixture takes the token as an argument.
const grant = arg('grant', null);
const k = P.loadKTests(ROOT).find((t) => t.id === rep);
const codec = F.codecFor(k);
const p = k.parameters || {};
const u32 = (t, i) => createHash('sha256').update(`${seed}:${t}:${i}`).digest().readUInt32LE(0);
function outcome(t) {
  switch (k.primitive) {
    case 'randomInt': { const r = p.max - p.min; return r <= 2 ** 32 ? p.min + (u32(t, 0) % r) : p.min + ((u32(t, 0) * 2 ** 16 + (u32(t, 1) & 0xffff)) % r); }
    case 'weightedPick': return u32(t, 0) % F.weightsFor(k).length;
    case 'shuffle': { const n = p.n ?? 52; const a = Array.from({ length: n }, (_, i) => i); for (let i = n - 1; i > 0; i--) { const x = u32(t, i) % (i + 1); [a[i], a[x]] = [a[x], a[i]]; } return a; }
    case 'sample': { const a = Array.from({ length: p.n }, (_, i) => i); for (let i = p.n - 1; i >= p.n - p.k; i--) { const x = u32(t, i) % (i + 1); [a[i], a[x]] = [a[x], a[i]]; } return a.slice(p.n - p.k).reverse(); }
    default: throw new Error('primitive');
  }
}
const out = (b) => { let o = 0; while (o < b.length) { try { o += writeSync(3, b, o); } catch (e) { if (e.code !== 'EAGAIN') throw e; } } };
const src = P.srcManifest(ROOT);
const loaded = src.list.filter(([f]) => ['src/index.ts', 'src/entropy/index.ts', 'src/mapping/index.ts', 'src/errors.ts'].includes(f)).map(([f, s]) => [f, fault === 'loaded' && f === 'src/entropy/index.ts' ? '0'.repeat(64) : s]);
// A25: the fixture reports the helper state the real preload would (mode, k, F and the backstop file digest).
const bsSha = createHash('sha256').update(readFileSync(join(ROOT, 'tools/ci/entropy-backstop.mjs'))).digest('hex');
const backstop = fault === 'h-nomode' ? null : { mode: P.HELPER_PLAN.mode, sample_k: P.HELPER_PLAN.sample_k + (fault === 'h-k' ? 1 : 0), first_walk: P.HELPER_PLAN.first_walk, part_floor: P.HELPER_PLAN.part_floor - (fault === 'h-floor' ? 1 : 0), backstop_sha256: fault === 'h-bs' ? 'b'.repeat(64) : bsSha, grant: fault === 'h-nogrant' ? null : fault === 'h-badgrant' ? `${grant}x` : grant };
const H = { run_id: runId, stream, rep, j: fault === 'h-j' ? j + 1 : j, calls: fault === 'h-n' ? calls + 1 : calls, src_before: fault === 'src-before' ? 'f'.repeat(64) : src.sha256, loaded, backstop, gate_leak_check: fault !== 'h-leak' };
if (fault === 'slow') Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3000); // still running when a sibling voids
if (fault !== 'no-h') out(F.jsonFrame(F.FRAME.H, H));
const n = fault === 'short' ? calls - 1 : fault === 'extra' ? calls + 1 : calls;
const h = createHash('sha256');
const per = Math.max(1, Math.floor(4096 / codec.bytes));
for (let c = 0; c < n; c += per) {
  const m = Math.min(per, n - c); const b = Buffer.alloc(m * codec.bytes);
  for (let i = 0; i < m; i++) codec.encode(outcome(off + c + i), b, i * codec.bytes);
  if (fault === 'shape' && c === 0) { if (codec.values > 1) { b[0] = b[codec.width]; } else b.fill(0xff, 0, codec.width); }
  h.update(b);
  out(fault === 'ragged' && c === 0 ? F.frame(F.FRAME.D, b.subarray(1)) : F.frame(F.FRAME.D, b));
}
if (fault === 'garbage') out(Buffer.from([0x5a, 1, 0, 0, 0, 0]));
const gc = fault === 't-floor' ? P.HELPER_PLAN.part_floor - 1 : 3 * Math.max(1, n) + 20000;
const T = { count: fault === 't-count' ? n + 1 : n, payload_sha256: fault === 't-digest' ? '0'.repeat(64) : h.digest('hex'), src_after: fault === 'src-after' ? 'e'.repeat(64) : src.sha256, a25: { gate_calls: gc, walks: P.expectedWalks(gc) - (fault === 't-walks' ? 1 : 0) } };
if (fault !== 'no-t') out(F.jsonFrame(F.FRAME.T, T));
if (fault === 'exit') process.exitCode = 3;
