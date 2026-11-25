// R-G64 streamed counting authority (design §3-§5; HoQ addendum 1 A22, D22-1..8). The parent process spawns N
// evidence helpers per stream (one call shape, Q2 B), decodes every frame itself, checks every outcome's shape,
// hashes each part (d_j), and counts a stream only when every part counts. Statistics are computed only after
// that (D22-8). Q3: fixed-width statistics use per-part exact integer accumulators summed in part order (parts
// are multiples of L, so no window straddles a boundary); sequential statistics (variable outcomes per
// observation) read an exact raw payload file in part order, re-hashed against d_j (option b); battery
// tools get one helper per battery stream piped through this launcher, no payload file (option a).
// Voids are on integrity grounds only (exit, trailer, count, digest, frame, shape, source); a voided attempt's
// accumulators are dropped and its statistic is never computed. Every attempt and its void reason is kept.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, rmSync, statfsSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FRAME, FrameReader, codecFor } from './stream-frames.mjs';
import { outcomeShapeError } from './collector.mjs';
import { ROOT, bindings, loadKTests, planDigest, reuseMismatches, srcManifest } from './run-plan.mjs';
import { assertEvidenceRunReady } from './evidence-entry.mjs';

const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const HELPER = join(ROOT, 'verification/harness/evidence-helper.mjs');
const sha = (b) => createHash('sha256').update(b).digest('hex');

// ---------------- one part ----------------
function partReader(ctx, j) {
  const { stream, kRep, codec, expect, attempt } = ctx;
  const want = stream.parts[j];
  const st = { j, reader: new FrameReader(), h: createHash('sha256'), count: 0, H: null, T: null, void: null, accs: ctx.consumers.fixed.map((c) => c.create()), payloadFd: null, payloadPath: null };
  if (ctx.consumers.seq.length) { st.payloadPath = join(ctx.runDir, `${stream.id}.a${attempt}.p${j}.payload`); st.payloadFd = openSync(st.payloadPath, 'w'); }
  const off = stream.parts.slice(0, j).reduce((a, b) => a + b, 0);
  const fail = (why) => { if (!st.void) st.void = `part ${j}: ${why}`; };
  const win = ctx.consumers.fixed.map((c) => ({ c, buf: [] }));
  st.onFrame = (f) => {
    if (st.void) return;
    if (f.type === FRAME.H) {
      if (st.H) return fail('second H frame');
      const h = f.json; st.H = h;
      if (h.run_id !== ctx.runId || h.stream !== stream.id || h.rep !== stream.rep) return fail('H names another run, stream or entry');
      if (h.j !== j || h.calls !== want) return fail(`H frame j/n_j ${h.j}/${h.calls} differs from the plan ${j}/${want}`);
      if (h.src_before !== expect.src.sha256) return fail('H src_before differs from the launcher srcDigest_before');
      const man = new Map(expect.src.list);
      if (!Array.isArray(h.loaded) || !h.loaded.some(([p]) => p === 'src/index.ts')) return fail('H has no load-hook digest of src/index.ts (D22-4)');
      for (const [p, s] of h.loaded) if (man.get(p) !== s) return fail(`src file ${p} as loaded differs from srcDigest_before (D22-4)`);
      return;
    }
    if (f.type === FRAME.D) {
      if (!st.H || st.T) return fail('D frame outside H..T');
      const b = f.payload;
      if (b.length === 0 || b.length % codec.bytes) return fail(`D payload ${b.length} is not whole outcomes of ${codec.bytes} bytes`);
      const m = b.length / codec.bytes;
      if (st.count + m > want) return fail(`more than n_j=${want} outcomes`);
      for (let i = 0; i < m; i++) {
        let v; try { v = codec.decode(b, i * codec.bytes); } catch (e) { return fail(e.message); }
        const bad = outcomeShapeError(kRep, v); if (bad) return fail(`outcome ${st.count + i}: ${bad}`);
        const call = off + st.count + i;
        for (let x = 0; x < win.length; x++) {
          const { c, buf } = win[x];
          if (Math.floor(call / c.w) >= c.M) continue;
          buf.push(v);
          if (buf.length === c.w) { st.accs[x].add(buf); buf.length = 0; }
        }
      }
      st.h.update(b); st.count += m;
      if (st.payloadFd !== null) writeSync(st.payloadFd, b);
      return;
    }
    if (st.T) return fail('second T frame');
    st.T = f.json;
  };
  st.finish = (code, signal) => {
    if (st.payloadFd !== null) { closeSync(st.payloadFd); st.payloadFd = null; }
    try { st.reader.end(); } catch (e) { fail(e.message); }
    if (code !== 0 || signal) fail(`helper exit ${code}${signal ? ` signal ${signal}` : ''}`);
    if (!st.H) fail('no H frame');
    if (!st.T) fail('no trailer');
    if (st.void) return;
    st.d = st.h.digest('hex');
    if (st.count !== want) return fail(`count ${st.count} != n_j ${want}`);
    if (st.T.count !== st.count) return fail(`trailer count ${st.T.count} != counted ${st.count}`);
    if (st.T.payload_sha256 !== st.d) return fail('trailer digest differs from the launcher d_j');
    if (st.T.src_after !== expect.src.sha256) return fail('src changed during the part (srcDigest_after)');
    if (win.some(({ buf }) => buf.length)) return fail('a window straddles the part end');
  };
  return st;
}

// ---------------- one stream: attempts until one counts (integrity voids only) ----------------
export async function runStreamCore(plan, stream, opts) {
  const { spawnPart, runDir, consumers = { fixed: [], seq: [] }, expect, maxAttempts = 3, kTests = loadKTests() } = opts;
  const kRep = kTests.find((k) => k.id === stream.rep);
  const codec = codecFor(kRep);
  if (codec.bytes !== stream.outcome_bytes) throw new Error(`${stream.id}: codec ${codec.bytes} B != plan ${stream.outcome_bytes} B`);
  mkdirSync(runDir, { recursive: true });
  const attempts = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const ctx = { stream, kRep, codec, expect, attempt, runId: plan.run_id, runDir, consumers };
    const parts = stream.parts.map((_, j) => partReader(ctx, j));
    const kids = [];
    const order = []; // void reasons in the order they happened; a part killed because another voided says so
    let killedBy = null;
    const noteVoid = (st) => { if (st.void && !order.includes(st.void)) order.push(st.void); };
    await Promise.all(parts.map((st) => new Promise((done) => {
      let child;
      try { child = spawnPart(stream, st.j, stream.parts[st.j]); } catch (e) { st.void = `part ${st.j}: spawn refused: ${e.message}`; noteVoid(st); return done(); }
      kids.push({ child, st });
      child.stdio[3].on('data', (chunk) => {
        // A part is killed only once it has sent data: its backstop is installed (and has proved it to a
        // preloaded parent) before the helper writes anything, so a kill never reads as a missing proof.
        if (killedBy !== null && !st.void) { child.kill('SIGKILL'); return; }
        if (st.void) return;
        try { for (const f of st.reader.push(chunk)) st.onFrame(f); } catch (e) { st.void = `part ${st.j}: ${e.message}`; }
        if (st.void) { noteVoid(st); killedBy ??= st.void; for (const k of kids) if (k.st.H !== null || k.st === st) k.child.kill('SIGKILL'); }
      });
      child.on('close', (code, signal) => {
        if (!st.void && killedBy !== null && signal === 'SIGKILL') st.void = `part ${st.j}: killed after ${killedBy}`;
        st.finish(code, signal); noteVoid(st); done();
      });
      child.on('error', (e) => { st.void ??= `part ${st.j}: ${e.message}`; });
    })));
    for (const p of parts) noteVoid(p);
    if (order.length) {
      attempts.push({ attempt, void: order[0], all_void_reasons: order });
      for (const p of parts) if (p.payloadPath) rmSync(p.payloadPath, { force: true });
      continue; // the voided attempt's accumulators are dropped here, never finished (D22-8)
    }
    attempts.push({ attempt, void: null });
    const d = parts.map((p) => p.d);
    const digest = sha(`${stream.id}\n${plan.run_id}\n${stream.parts.join(',')}\n${d.join('\n')}`);
    return { counted: true, stream: stream.id, attempts, d, digest, parts, payloadFiles: parts.map((p) => p.payloadPath) };
  }
  return { counted: false, stream: stream.id, attempts, d: null, digest: null, parts: null, payloadFiles: [] };
}

// D22-8: statistics only for a counted stream; never for a voided attempt.
export function streamStatistics(res, stream, consumers, codec) {
  if (!res || res.counted !== true || res.attempts.at(-1)?.void !== null) throw new Error(`${stream.id}: statistic refused: stream not counted (D22-8)`);
  const N = stream.parts.length; // the plan's N, never a count the result or a header carries
  if (!Array.isArray(res.parts) || res.parts.length !== N || !Array.isArray(res.d) || res.d.length !== N) throw new Error(`${stream.id}: statistic refused: counted parts differ from the plan's ${N}`);
  const out = {};
  consumers.fixed.forEach((c, x) => {
    const merged = c.create();
    for (let j = 0; j < N; j++) merged.merge(res.parts[j].accs[x]); // part order
    out[c.id] = c.finish(merged);
  });
  for (const c of consumers.seq) out[c.id] = c.run(payloadReader(res, codec), { stream: stream.id });
  return out;
}

// Q3 (b): the raw payload files, read in part order; each part is re-hashed against d_j before any of it is used.
export function payloadReader(res, codec) {
  let j = -1, buf = null, pos = 0;
  const load = () => {
    j += 1;
    if (j >= res.payloadFiles.length) throw new Error(`payload files exhausted after ${res.payloadFiles.length} parts`);
    buf = readFileSync(res.payloadFiles[j]); pos = 0;
    if (sha(buf) !== res.d[j]) throw new Error(`payload file part ${j} differs from d_j (Q3 b)`);
  };
  return () => {
    while (buf === null || pos >= buf.length) load();
    const v = codec.decode(buf, pos); pos += codec.bytes; return v;
  };
}

// ---------------- wave-1 consumers (THE wave-1 statistic module) ----------------
export async function wave1Consumers(stream, { observations = {} } = {}) {
  const S = await import('../statistic/wave1-statistic.mjs');
  const fixed = [], seq = [];
  for (const ent of stream.entries) {
    const e = S.ENTRIES.find((x) => x.id === ent.id);
    if (!e) continue;
    if (e.kind === 'adj') {
      const M = ent.M;
      const lumped = S.lumpExact(S.lawExact(e), M);
      const n = lumped.map.length;
      fixed.push({ id: e.id, w: 1, M, create() { const h = new Float64Array(n); return { h, add(win) { const { k } = S.observe(e, () => win[0]); h[Math.min(k, n - 1)] += 1; }, merge(o) { for (let i = 0; i < n; i++) h[i] += o.h[i]; } }; },
        finish(a) { return { id: e.id, ...S.pearson(a.h, lumped, M), outcomes: M, statistic: S.STATISTIC_ID }; } });
    } else {
      const M = observations[e.id];
      if (!Number.isSafeInteger(M) || M < 1) throw new Error(`${e.id}: observations must be pre-registered in the plan`);
      seq.push({ id: e.id, run(next) { const lumped = S.lumpExact(S.lawExact(e), M); const { h, outcomes } = S.histogram(e, M, next, lumped.map.length); return { id: e.id, ...S.pearson(h, lumped, M), outcomes, statistic: S.STATISTIC_ID }; } });
    }
  }
  return { fixed, seq };
}

// ---------------- D22-5: evidence only from a dedicated pinned clone ----------------
export const CLONE_MARK = 'evidence-clone.json';
export function prepareEvidenceClone(origin, commit, dir) {
  const g = (args, cwd) => { const r = spawnSync('git', args, { cwd, encoding: 'utf8' }); if (r.status !== 0) throw new Error(`git ${args[0]}: ${r.stderr}`); return r.stdout.trim(); };
  g(['clone', '--no-hardlinks', '--quiet', origin, dir]);
  g(['checkout', '--quiet', '--detach', commit], dir);
  const head = g(['rev-parse', 'HEAD'], dir), tree = g(['rev-parse', 'HEAD^{tree}'], dir);
  writeFileSync(join(dir, '.git', CLONE_MARK), JSON.stringify({ head, tree }));
  return { head, tree };
}
export function pinnedCloneState(root, pinned) {
  const g = (args) => { const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' }); return r.status === 0 ? r.stdout.trim() : null; };
  const head = g(['rev-parse', 'HEAD']), tree = g(['rev-parse', 'HEAD^{tree}']);
  const dirty = g(['status', '--porcelain', '--untracked-files=all']);
  let mark = null; try { mark = JSON.parse(readFileSync(join(root, '.git', CLONE_MARK), 'utf8')); } catch { /* none */ }
  const why = [];
  if (!mark) why.push('not a dedicated evidence clone (no .git/evidence-clone.json)');
  if (head === null || tree === null) why.push('not a git work tree');
  if (dirty !== '') why.push(`tree not clean: ${String(dirty).split('\n').slice(0, 3).join('; ')}`);
  if (mark && (mark.head !== head || mark.tree !== tree)) why.push('HEAD moved since the clone was made');
  if (pinned && (pinned.head !== head || pinned.tree !== tree)) why.push(`HEAD ${head} / tree ${tree} is not the pinned ${pinned.head} / ${pinned.tree}`);
  return { head, tree, clean: dirty === '', ok: why.length === 0, why };
}

// D22-6 disk: a stream's payload file must fit (raw bytes, plus 5%).
export function payloadBytes(stream, consumers) { return consumers.seq.length ? stream.calls * stream.outcome_bytes : 0; }
export function assertDisk(dir, bytes) {
  const s = statfsSync(dir); const free = Number(s.bavail) * Number(s.bsize);
  if (bytes * 1.05 > free) throw new Error(`disk: need ${bytes} bytes of payload file (+5%), ${free} free in ${dir} (D22-6)`);
  return free;
}

// ---------------- the counting authority ----------------
const COUNTED = new WeakMap();
export function streamCounted(r) { return r !== null && typeof r === 'object' && COUNTED.get(r) === r.digest && typeof r.digest === 'string'; }

export function header(plan, bind, clone) {
  return { plan_digest: planDigest(plan), run_id: plan.run_id, M_per_entry: plan.M_per_entry, stream_map: plan.stream_map, counting_rule: plan.counting_rule, bindings: bind, clone };
}

function realSpawnPart(plan) {
  return (stream, j, calls) => {
    const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.ENTROPY_BACKSTOP_CHANNEL;
    return spawn(process.execPath, ['--import', BACKSTOP, HELPER, '--run', plan.run_id, '--stream', stream.id, '--rep', stream.rep, '--j', String(j), '--calls', String(calls)],
      { cwd: ROOT, env, stdio: ['ignore', 'ignore', 'inherit', 'pipe'] });
  };
}

// Runs every stream of the plan from the dedicated pinned clone this module is loaded from.
export async function runStreamPlan(plan, { runDir, pinned, observations = {}, maxAttempts = 3, onStream = null } = {}) {
  assertEvidenceRunReady(ROOT);
  const clone = pinnedCloneState(ROOT, pinned);
  if (!clone.ok) throw new Error(`evidence refused (D22-5): ${clone.why.join('; ')}`);
  const bind = bindings(ROOT);
  const head = header(plan, bind, { head: clone.head, tree: clone.tree, clean: clone.clean });
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, 'header.json'), JSON.stringify(head, null, 1));
  const expect = { src: srcManifest(ROOT) };
  if (expect.src.sha256 !== bind.src_digest) throw new Error('src changed while binding');
  const results = [];
  for (const stream of plan.streams) {
    const consumers = await wave1Consumers(stream, { observations });
    const rec = join(runDir, `${stream.id}.json`);
    if (existsSync(rec)) {
      const prev = JSON.parse(readFileSync(rec, 'utf8'));
      const bad = reuseMismatches(prev.bindings, bind);
      if (bad.length) throw new Error(`${stream.id}: checkpoint not reusable: ${bad.join(', ')} (D22-7)`);
    }
    assertDisk(runDir, payloadBytes(stream, consumers));
    const res = await runStreamCore(plan, stream, { spawnPart: realSpawnPart(plan), runDir, consumers, expect, maxAttempts });
    const out = { stream: stream.id, counted: res.counted, attempts: res.attempts, d: res.d, digest: res.digest, entries: stream.entries.map((e) => e.id), bindings: bind };
    if (res.counted) {
      COUNTED.set(out, out.digest);
      out.statistics = streamStatistics(res, stream, consumers, codecFor(loadKTests(ROOT).find((k) => k.id === stream.rep)));
      for (const s of res.payloadFiles) if (s) rmSync(s, { force: true });
    }
    writeFileSync(rec, JSON.stringify(out, null, 1));
    results.push(out);
    if (onStream) onStream(out);
  }
  return { header: head, results };
}
