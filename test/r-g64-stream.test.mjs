// R-G64 streamed harness (design verification/r-g64-design.md; HoQ addendum 1 A22, D22-1..8). Mutants of the
// files tested here are in tools/ci/j-calib-mutants.mjs (RS-*) and tools/ci/g39-mutants.mjs (RS-B*).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as F from '../verification/harness/stream-frames.mjs';
import * as P from '../verification/harness/run-plan.mjs';
import * as L from '../verification/harness/stream-launcher.mjs';
import * as S from '../verification/statistic/wave1-statistic.mjs';
import { statisticFromRecords } from '../verification/harness/wave1-evidence.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FAKE = join(ROOT, 'test/fixtures/r-g64-fake-helper.mjs');
const K = P.loadKTests(ROOT);
const kOf = (id) => K.find((k) => k.id === id);
const env = () => ({ ...process.env }); // under npm test the children load the backstop too (and prove it)
const tmp = (p) => mkdtempSync(join(tmpdir(), `rg64-${p}-`));

// spawnPart for the fixture: the same global sequence whatever the partition. faults: { 'attempt:j': fault }.
function fakeSpawn(plan, { seed = 's', faults = {} } = {}) {
  const tries = new Map();
  return (stream, j, calls) => {
    const a = (tries.get(`${stream.id}:${j}`) ?? 0) + 1; tries.set(`${stream.id}:${j}`, a);
    const off = stream.parts.slice(0, j).reduce((x, y) => x + y, 0);
    const fault = faults[`${a}:${j}`] ?? 'none';
    return spawn(process.execPath, [FAKE, '--run', plan.run_id, '--stream', stream.id, '--rep', stream.rep, '--j', String(j), '--calls', String(calls), '--off', String(off), '--seed', seed, '--fault', fault],
      { env: env(), stdio: ['ignore', 'ignore', 'inherit', 'pipe'] });
  };
}
const expect = () => ({ src: P.srcManifest(ROOT) });
// The same sequence, one pass, in this process (what the fixture emits for global indices 0..n-1).
function onePass(rep, n, seed = 's') {
  const r = spawnSync(process.execPath, [FAKE, '--run', 'x', '--stream', 'x', '--rep', rep, '--j', '0', '--calls', String(n), '--off', '0', '--seed', seed], { env: env(), stdio: ['ignore', 'ignore', 'inherit', 'pipe'], maxBuffer: 1 << 28 });
  const rd = new F.FrameReader(); const c = F.codecFor(kOf(rep)); const v = [];
  for (const f of rd.push(r.output[3])) if (f.type === F.FRAME.D) for (let i = 0; i < f.payload.length; i += c.bytes) v.push(c.decode(f.payload, i));
  return v;
}

test('frames: round trip; unknown type, oversize payload and trailing bytes are integrity errors', () => {
  const r = new F.FrameReader();
  const b = Buffer.concat([F.jsonFrame(F.FRAME.H, { a: 1 }), F.frame(F.FRAME.D, Buffer.from([1, 2, 3])), F.jsonFrame(F.FRAME.T, { c: 3 })]);
  const got = [...r.push(b.subarray(0, 7)), ...r.push(b.subarray(7))];
  assert.deepEqual(got.map((f) => f.type), [F.FRAME.H, F.FRAME.D, F.FRAME.T]);
  assert.deepEqual([...got[1].payload], [1, 2, 3]); r.end();
  assert.throws(() => new F.FrameReader().push(Buffer.from([0x5a, 0, 0, 0, 0])), /unknown type/);
  const big = Buffer.alloc(5); big[0] = F.FRAME.D; big.writeUInt32LE(F.MAX_DATA + 1, 1);
  assert.throws(() => new F.FrameReader().push(big), /over its limit/);
  const t = new F.FrameReader(); t.push(Buffer.from([F.FRAME.D, 9, 0])); assert.throws(() => t.end(), /trailing/);
});

test('codec: exact for every K call shape, including [0, 2^48) and shuffle n=1000', () => {
  for (const k of K) {
    const c = F.codecFor(k); const b = Buffer.alloc(c.bytes);
    const p = k.parameters;
    const v = k.primitive === 'randomInt' ? p.max - 1 : k.primitive === 'weightedPick' ? F.weightsFor(k).length - 1
      : k.primitive === 'shuffle' ? Array.from({ length: p.n }, (_, i) => p.n - 1 - i) : Array.from({ length: p.k }, (_, i) => p.n - 1 - i);
    c.encode(v, b, 0); assert.deepEqual(c.decode(b, 0), v, k.id);
  }
  assert.throws(() => F.codecFor(kOf('randomInt/chi2/min-0-max-2')).encode(2, Buffer.alloc(1), 0), /outside/);
});

test('D22-6: outcome keys are exact up to 128 bits and sha256-128 only above', () => {
  const a = Buffer.alloc(16, 7), b = Buffer.alloc(17, 7);
  assert.equal(F.outcomeKey(a), `x${a.toString('hex')}`);
  assert.equal(F.outcomeKey(b), `h${createHash('sha256').update(b).digest('hex').slice(0, 32)}`);
  assert.notEqual(F.outcomeKey(Buffer.from([1])), F.outcomeKey(Buffer.from([1, 0])), 'exact keys keep the length');
});

test('plan: n_j = floor(M/N) + (j < M mod N); M is a parameter; one shared stream per shape; parts are multiples of L', () => {
  assert.deepEqual(P.partition(10, 4), [3, 3, 2, 2]);
  assert.deepEqual(P.partition(8, 8), Array(8).fill(1));
  assert.throws(() => P.partition(3, 4)); assert.throws(() => P.partition(0, 1));
  const M = Object.fromEntries(K.map((k) => [k.id, 1000 + (k.id.length % 7)]));
  const plan = P.buildPlan({ runId: 'r', M, N: 7 });
  assert.equal(plan.streams.length, 24);
  for (const s of plan.streams) {
    assert.equal(s.parts.reduce((a, b) => a + b, 0), s.calls);
    for (const n of s.parts) assert.equal(n % s.L, 0, `${s.id} part not a multiple of L`);
    for (const e of s.entries) { assert.ok(s.calls >= e.M * e.w); assert.equal(plan.stream_map[e.id], s.id); }
  }
  assert.equal(Object.keys(plan.stream_map).length, K.length);
  assert.throws(() => P.buildPlan({ runId: 'r', N: 2 }), /M per entry/);
  const two = P.buildPlan({ runId: 'r2', M: { 'shuffle/positional/n-104': 10 }, N: 2, prefix: 'R2-' });
  assert.equal(two.streams[0].id, 'R2-01');
});

async function runFake(ids, { M, N, observations = {}, faults = {}, maxAttempts = 3, seed } = {}) {
  const plan = P.buildPlan({ runId: 'rt', M: Object.fromEntries(ids.map((id) => [id, M[id] ?? M])), N });
  const stream = plan.streams[0];
  const dir = tmp('run');
  try {
    const consumers = await L.wave1Consumers(stream, { observations });
    const res = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan, { faults, seed }), runDir: dir, consumers, expect: expect(), maxAttempts });
    const stats = res.counted ? L.streamStatistics(res, stream, consumers, F.codecFor(kOf(stream.rep))) : null;
    return { plan, stream, res, stats, consumers };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('merge equals one pass: adjacency (fixed accumulators) for N = 1, 3, 5 equals the one-pass wave-1 statistic', async () => {
  const id = 'shuffle/adjacency-mod4/n-52';
  const one = statisticFromRecords(S.ENTRIES.find((e) => e.id === id), onePass(id, 600), 600);
  for (const N of [1, 3, 5]) {
    const { res, stats } = await runFake([id], { M: 600, N });
    assert.equal(res.counted, true, JSON.stringify(res.attempts));
    assert.equal(stats[id].x2, one.x2, `N=${N}`); assert.equal(stats[id].df, one.df);
  }
});

test('merge equals one pass: coupon and duplicates (sequential, payload files in part order) for N = 1, 2, 4', async () => {
  for (const [id, calls, obs] of [['randomInt/coupon-collector/min-0-max-2', 3000, 300], ['randomInt/duplicates/min-0-max-4294967296', 4096 * 40, 40]]) {
    const want = statisticFromRecords(S.ENTRIES.find((e) => e.id === id), onePass(id, calls), obs);
    assert.equal(typeof want.x2, 'number'); assert.ok(want.outcomes > 0);
    for (const N of [1, 2, 4]) {
      const { res, stats } = await runFake([id], { M: calls, N, observations: { [id]: obs } });
      assert.equal(res.counted, true, JSON.stringify(res.attempts));
      assert.equal(stats[id].x2, want.x2, `${id} N=${N}`); assert.equal(stats[id].outcomes, want.outcomes);
    }
  }
});

test('D22-3: a shared stream read as w=1 values and w=2 windows; windows never straddle parts; merge equals one pass', async () => {
  const plan = P.buildPlan({ runId: 'rt', M: { 'randomInt/chi2/min-0-max-38': 50, 'randomInt/ordered-pair-chi2/min-0-max-38': 40 }, N: 3 });
  const stream = plan.streams[0];
  assert.equal(stream.L, 2); assert.equal(stream.calls, 80);
  const pairCount = (w, M) => ({ id: `pairs-${w}`, w, M, create() { const m = new Map(); return { m, add(win) { const key = win.join(','); m.set(key, (m.get(key) ?? 0) + 1); }, merge(o) { for (const [a, b] of o.m) m.set(a, (m.get(a) ?? 0) + b); } }; }, finish(a) { return [...a.m].sort(); } });
  const consumers = { fixed: [pairCount(1, 50), pairCount(2, 40)], seq: [] };
  const dir = tmp('w');
  try {
    const res = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan), runDir: dir, consumers, expect: expect() });
    const st = L.streamStatistics(res, stream, consumers, F.codecFor(kOf(stream.rep)));
    const v = onePass(stream.rep, 80);
    const tally = (arr) => { const m = new Map(); for (const k of arr) m.set(k, (m.get(k) ?? 0) + 1); return [...m].sort(); };
    assert.deepEqual(st['pairs-1'], tally(v.slice(0, 50).map(String)));
    assert.deepEqual(st['pairs-2'], tally(Array.from({ length: 40 }, (_, t) => `${v[2 * t]},${v[2 * t + 1]}`)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

const FAULTS = [
  ['exit', /helper exit 3/], ['no-t', /no trailer/], ['no-h', /D frame outside H..T|no H frame/], ['short', /count \d+ != n_j/],
  ['extra', /more than n_j/], ['t-count', /trailer count/], ['t-digest', /trailer digest differs/], ['shape', /outcome 0: /],
  ['ragged', /not whole outcomes/], ['garbage', /unknown type/], ['h-j', /H frame j\/n_j/], ['h-n', /H frame j\/n_j/],
  ['src-before', /src_before/], ['src-after', /srcDigest_after/], ['loaded', /as loaded differs .*D22-4/],
  ['h-nomode', /not in A25 mode/], ['h-k', /differs from the plan a25\/k=\d+.*A25-4/], ['h-bs', /backstop digest differs.*A25-1/], ['h-leak', /leak check did not run/], ['t-walks', /trailer A25 walks .*A25-4/], ['h-floor', /part floor \d+ differs from the plan .*A25-4b/],
];
for (const [fault, why] of FAULTS) {
  test(`D22-8 integrity void: ${fault} voids the attempt, the void reason is kept, no statistic is computed`, async () => {
    const id = 'shuffle/adjacency-mod4/n-52';
    const { res, stream, consumers } = await runFake([id], { M: 40, N: 2, faults: { '1:1': fault }, maxAttempts: 1 });
    assert.equal(res.counted, false);
    assert.equal(res.attempts.length, 1); assert.match(res.attempts[0].void, why);
    assert.throws(() => L.streamStatistics(res, stream, consumers, null), /not counted \(D22-8\)/);
  });
}

test('D22-8: a voided attempt is re-run from scratch; attempts and reasons are listed; only the counted attempt is used', async () => {
  const id = 'shuffle/adjacency-mod4/n-52';
  const { res, stats } = await runFake([id], { M: 60, N: 3, faults: { '1:2': 't-digest' } });
  assert.equal(res.counted, true);
  assert.deepEqual(res.attempts.map((a) => a.void === null), [false, true]);
  assert.match(res.attempts[0].void, /part 2: trailer digest/);
  const one = statisticFromRecords(S.ENTRIES.find((e) => e.id === id), onePass(id, 60), 60);
  assert.equal(stats[id].x2, one.x2);
});

test('D22-8: the void that happened first is the attempt reason; a part killed because of it says so', async () => {
  const { res } = await runFake(['shuffle/adjacency-mod4/n-52'], { M: 40, N: 2, faults: { '1:0': 'slow', '1:1': 'garbage' }, maxAttempts: 1 });
  assert.equal(res.counted, false);
  assert.match(res.attempts[0].void, /^part 1: .*unknown type/);
  assert.match(res.attempts[0].all_void_reasons[1], /^part 0: killed after part 1: /);
});

test('Q3: fixed accumulators are merged in part order', async () => {
  const plan = P.buildPlan({ runId: 'rt', M: { 'shuffle/adjacency-mod4/n-52': 30 }, N: 3 });
  const stream = plan.streams[0];
  const seqAcc = { id: 'order', w: 1, M: 30, create() { const a = { first: [], add(win) { if (!a.first.length) a.first.push(win[0].join(',')); }, merge(o) { a.first.push(...o.first); } }; return a; }, finish(a) { return a.first; } };
  const consumers = { fixed: [seqAcc], seq: [] };
  const dir = tmp('ord');
  try {
    const res = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan), runDir: dir, consumers, expect: expect() });
    const v = onePass(stream.rep, 30);
    assert.deepEqual(L.streamStatistics(res, stream, consumers, null).order, [0, 10, 20].map((t) => v[t].join(',')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D22-8 / A22: a statistic is never computed for a voided attempt, nor for parts that differ from the plan', async () => {
  const id = 'shuffle/adjacency-mod4/n-52';
  const { res, stream, consumers } = await runFake([id], { M: 30, N: 3 });
  const codec = F.codecFor(kOf(stream.rep));
  assert.throws(() => L.streamStatistics({ ...res, attempts: [...res.attempts, { attempt: 9, void: 'part 0: x' }] }, stream, consumers, codec), /D22-8/);
  const extra = { ...res, parts: [...res.parts, res.parts[0]], d: [...res.d, res.d[0]] };
  assert.throws(() => L.streamStatistics(extra, stream, consumers, codec), /differ from the plan/);
  const fewer = { ...res, parts: res.parts.slice(1), d: res.d.slice(1) };
  assert.throws(() => L.streamStatistics(fewer, stream, consumers, codec), /differ from the plan/);
});

test('Q3 (b): the payload file is re-hashed against d_j before use; a changed byte is refused', async () => {
  const id = 'randomInt/coupon-collector/min-1-max-7';
  const plan = P.buildPlan({ runId: 'rt', M: { [id]: 400 }, N: 2 });
  const stream = plan.streams[0];
  const dir = tmp('sp');
  try {
    const consumers = await L.wave1Consumers(stream, { observations: { [id]: 5 } });
    const res = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan), runDir: dir, consumers, expect: expect() });
    assert.equal(res.counted, true);
    const codec = F.codecFor(kOf(stream.rep));
    const next = L.payloadReader(res, codec); assert.equal(typeof next(), 'number');
    const b = readFileSync(res.payloadFiles[0]); b[0] ^= 1; writeFileSync(res.payloadFiles[0], b);
    assert.throws(() => L.payloadReader(res, codec)(), /differs from d_j/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D22-7: a checkpoint is reusable only when every bound sha256, node version and binary, and src digest are equal', () => {
  const b = P.bindings(ROOT);
  assert.deepEqual(P.reuseMismatches(b, structuredClone(b)), []);
  for (const f of ['verification/k-tests-v1.1.json', 'verification/harness/collector.mjs', 'verification/harness/wave1-evidence.mjs', 'verification/harness/evidence-entry.mjs', 'tools/ci/entropy-backstop.mjs']) {
    assert.ok(f in b.files, f);
    const c = structuredClone(b); c.files[f] = '0'.repeat(64);
    assert.deepEqual(P.reuseMismatches(b, c), [`sha256 of ${f}`]);
  }
  for (const k of ['node_version', 'node_binary_sha256', 'src_digest']) { const c = structuredClone(b); c[k] = 'x'; assert.deepEqual(P.reuseMismatches(b, c), [k]); }
  assert.match(b.node_binary_sha256, /^[0-9a-f]{64}$/); assert.equal(b.node_version, process.version);
});

test('D22-6: the payload file must fit on disk before a stream starts', () => {
  assert.ok(L.assertDisk(tmpdir(), 1) > 0);
  assert.throws(() => L.assertDisk(tmpdir(), 2 ** 60), /D22-6/);
  const s = { calls: 10, outcome_bytes: 52 };
  assert.equal(L.payloadBytes(s, { seq: [1] }), 520); assert.equal(L.payloadBytes(s, { seq: [] }), 0);
});

// A one-commit repository written as loose objects (the backstop's git allowlist has no commit subcommand).
function oneCommitRepo(dir, files) {
  const g = (args, cwd) => { const r = spawnSync('git', args, { cwd, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
  g(['init', '--quiet', dir]);
  const put = (type, body) => {
    const raw = Buffer.concat([Buffer.from(`${type} ${body.length}\0`), body]);
    const id = createHash('sha1').update(raw).digest('hex');
    mkdirSync(join(dir, '.git/objects', id.slice(0, 2)), { recursive: true });
    writeFileSync(join(dir, '.git/objects', id.slice(0, 2), id.slice(2)), deflateSync(raw));
    return id;
  };
  const tree = put('tree', Buffer.concat(Object.keys(files).sort().map((n) => Buffer.concat([Buffer.from(`100644 ${n}\0`), Buffer.from(put('blob', Buffer.from(files[n])), 'hex')]))));
  const head = put('commit', Buffer.from(`tree ${tree}\nauthor t <t@t> 0 +0000\ncommitter t <t@t> 0 +0000\n\na\n`));
  writeFileSync(join(dir, '.git/refs/heads/r-g64'), `${head}\n`); writeFileSync(join(dir, '.git/HEAD'), 'ref: refs/heads/r-g64\n');
  return { head, tree };
}

test('D22-5: evidence only from a dedicated, clean clone at the pinned HEAD and tree', () => {
  const d = tmp('clone');
  try {
    const o = join(d, 'origin');
    const { head, tree } = oneCommitRepo(o, { 'a.txt': '1' });
    assert.equal(L.pinnedCloneState(o, { head, tree }).ok, false, 'the origin itself is not a dedicated clone');
    const c = join(d, 'clone'); const pin = L.prepareEvidenceClone(o, head, c);
    assert.deepEqual(pin, { head, tree });
    assert.deepEqual(L.pinnedCloneState(c, pin), { head, tree, clean: true, ok: true, why: [] });
    assert.match(L.pinnedCloneState(c, { head: '0'.repeat(40), tree }).why.join(), /not the pinned/);
    writeFileSync(join(c, 'stray.txt'), 'x');
    const s = L.pinnedCloneState(c, pin); assert.equal(s.ok, false); assert.equal(s.clean, false); assert.match(s.why.join(), /not clean/);
    rmSync(join(c, 'stray.txt'));
    writeFileSync(join(c, 'a.txt'), '2'); assert.match(L.pinnedCloneState(c, pin).why.join(), /not clean/);
    writeFileSync(join(c, 'a.txt'), '1'); assert.equal(L.pinnedCloneState(c, pin).ok, true);
    rmSync(join(c, '.git', L.CLONE_MARK)); assert.match(L.pinnedCloneState(c, pin).why.join(), /not a dedicated evidence clone/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('runStreamPlan checks readiness before anything else (NOT-READY: nothing spawned, nothing written)', async () => {
  const d = tmp('nr');
  try {
    const plan = P.buildPlan({ runId: 'nr', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1, counted: true });
    await assert.rejects(L.runStreamPlan(plan, { runDir: join(d, 'run') }), /harness NOT-READY/);
    assert.equal(existsSync(join(d, 'run')), false);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('D22-4 + real helper: the evidence helper under the backstop counts, and its load-hook list matches srcDigest_before', async () => {
  const id = 'shuffle/adjacency-mod4/n-52';
  const plan = P.buildPlan({ runId: 'real', M: { [id]: 40 }, N: 2 });
  const stream = plan.streams[0];
  const dir = tmp('real');
  const spawnPart = (s, j, calls) => spawn(process.execPath, ['--import', join(ROOT, 'tools/ci/entropy-backstop.mjs'), join(ROOT, 'verification/harness/evidence-helper.mjs'), '--run', 'real', '--stream', s.id, '--rep', s.rep, '--j', String(j), '--calls', String(calls)], { env: { ...env(), ENTROPY_BACKSTOP_HELPER: 'a25' }, stdio: ['ignore', 'ignore', 'inherit', 'pipe'] });
  try {
    const consumers = await L.wave1Consumers(stream);
    const res = await L.runStreamCore(plan, stream, { spawnPart, runDir: dir, consumers, expect: expect() });
    assert.equal(res.counted, true, JSON.stringify(res.attempts));
    assert.ok(res.parts.every((p) => p.H.loaded.some(([f]) => f === 'src/entropy/index.ts')));
    const st = L.streamStatistics(res, stream, consumers, F.codecFor(kOf(stream.rep)));
    assert.equal(st[id].outcomes, 40);
    const bad = await L.runStreamCore(plan, stream, { spawnPart, runDir: dir, consumers, expect: { src: { ...expect().src, list: expect().src.list.map(([f, s]) => [f, f === 'src/errors.ts' ? '1'.repeat(64) : s]) } }, maxAttempts: 1 });
    assert.match(bad.attempts[0].void, /src\/errors\.ts as loaded differs .*D22-4/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------- A25-4b: part floor for counted runs (CTO answer b) ----------
test('A25-4b: the plan carries the part floor F + 20 * 2^k and a counted flag (default false); the header shows both', () => {
  const H = P.HELPER_PLAN;
  assert.equal(H.part_floor, H.first_walk + H.min_sampled_hits * 2 ** H.sample_k);
  assert.equal(H.part_floor, 91920);
  const a = P.buildPlan({ runId: 'f', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1 });
  assert.equal(a.counted, false); assert.equal(a.helper.part_floor, 91920);
  assert.equal(P.buildPlan({ runId: 'f', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1, counted: true }).counted, true);
  assert.throws(() => P.buildPlan({ runId: 'f', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1, counted: 'yes' }), /counted must be true or false/);
  assert.equal(L.header(a, {}, {}).counted, false); assert.equal(L.header(a, {}, {}).helper.part_floor, 91920);
});
test('A25-4b: a counted plan with a part below the floor is refused before any part is spawned', async () => {
  const plan = P.buildPlan({ runId: 'cf', M: { 'shuffle/adjacency-mod4/n-52': 40 }, N: 2, counted: true });
  const stream = plan.streams[0]; const dir = tmp('cf'); let spawned = 0;
  try {
    const consumers = await L.wave1Consumers(stream);
    await assert.rejects(L.runStreamCore(plan, stream, { spawnPart: (...a) => { spawned++; return fakeSpawn(plan)(...a); }, runDir: dir, consumers, expect: expect() }), /counted plan part 0 has 20 outcomes, below the A25 part floor 91920 .*A25-4b/);
    assert.equal(spawned, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('A25-4b: a counted part at the floor counts; one whose trailer reports fewer gate calls than the floor voids', async () => {
  const id = 'randomInt/chi2/min-0-max-38';
  const plan = P.buildPlan({ runId: 'cf2', M: { [id]: P.HELPER_PLAN.part_floor }, N: 1, counted: true });
  const stream = plan.streams[0]; const dir = tmp('cf2');
  assert.equal(stream.parts[0], P.HELPER_PLAN.part_floor);
  try {
    const consumers = await L.wave1Consumers(stream);
    const ok = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan), runDir: dir, consumers, expect: expect(), maxAttempts: 1 });
    assert.equal(ok.counted, true, JSON.stringify(ok.attempts));
    const bad = await L.runStreamCore(plan, stream, { spawnPart: fakeSpawn(plan, { faults: { '1:0': 't-floor' } }), runDir: dir, consumers, expect: expect(), maxAttempts: 1 });
    assert.equal(bad.counted, false); assert.match(bad.attempts[0].void, /gate calls 91919 below the part floor 91920 in a counted run .*A25-4b/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('A25-4b: runStreamPlan (the evidence path) refuses a plan that is not counted; nothing is written', async () => {
  const d = tmp('nc');
  try {
    const plan = P.buildPlan({ runId: 'nc', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1 });
    await assert.rejects(L.runStreamPlan(plan, { runDir: join(d, 'run') }), /counted plans only .*A25-4b/);
    assert.equal(existsSync(join(d, 'run')), false);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
