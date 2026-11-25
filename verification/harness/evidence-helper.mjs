#!/usr/bin/env node
// R-G64 evidence helper (design §3; HoQ addendum 1 D22-4). Started only by stream-launcher.mjs, under the
// entropy-backstop preload, with fd 3 as its only output channel. It makes `calls` public calls of ONE call
// shape (the K entry `rep`, read from this tree's k-tests) and writes them, exactly encoded, as frames:
//   H { run_id, stream, rep, j, calls, src_before, loaded }   D <outcome bytes>...   T { count, payload_sha256, src_after }
// D22-4: a module load hook hashes every src/ file AS LOADED (the bytes node compiles), before the engine is
// imported; the launcher compares that list with its own srcDigest_before. The helper asserts nothing the
// launcher believes: H and T are claims the launcher re-derives or checks against its own reading.
import { registerHooks } from 'node:module';
import { createHash } from 'node:crypto';
import { writeSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SRC = pathToFileURL(join(ROOT, 'src')).href + '/';
const loaded = [];
registerHooks({
  load(url, context, nextLoad) {
    const r = nextLoad(url, context);
    if (url.startsWith(SRC)) loaded.push([relative(ROOT, fileURLToPath(url)), createHash('sha256').update(r.source ?? '').digest('hex')]);
    return r;
  },
});

const { FRAME, frame, jsonFrame, codecFor, weightsFor } = await import('./stream-frames.mjs');
const { srcManifest, loadKTests } = await import('./run-plan.mjs');

const arg = (name) => { const i = process.argv.indexOf(`--${name}`); if (i < 0 || i + 1 >= process.argv.length) throw new Error(`helper: --${name} missing`); return process.argv[i + 1]; };
const runId = arg('run'), stream = arg('stream'), rep = arg('rep'), j = Number(arg('j')), calls = Number(arg('calls'));
if (!Number.isSafeInteger(j) || j < 0 || !Number.isSafeInteger(calls) || calls < 1) throw new Error('helper: bad j or calls');
const k = loadKTests(ROOT).find((t) => t.id === rep);
if (!k) throw new Error(`helper: ${rep} is not a K entry`);

const out = (b) => {
  let off = 0;
  while (off < b.length) {
    try { off += writeSync(3, b, off); }
    catch (e) { if (e.code !== 'EAGAIN') throw e; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2); }
  }
};

const before = srcManifest(ROOT);
const E = await import(pathToFileURL(join(ROOT, 'src/index.ts')).href);
const p = k.parameters || {};
let call;
switch (k.primitive) {
  case 'randomInt': call = () => E.integer(p.min, p.max); break;
  case 'shuffle': { const d = Array.from({ length: p.n ?? 52 }, (_, i) => i); call = () => E.shuffle(d); break; }
  case 'sample': call = () => E.sample(p.n, p.k); break;
  case 'weightedPick': { const w = weightsFor(k); call = () => E.weightedPick(w); break; }
  default: throw new Error(`helper: unknown primitive ${k.primitive}`);
}
const codec = codecFor(k);
out(jsonFrame(FRAME.H, { run_id: runId, stream, rep, j, calls, src_before: before.sha256, loaded }));
const per = Math.max(1, Math.floor((1 << 16) / codec.bytes));
const buf = Buffer.allocUnsafe(per * codec.bytes);
const h = createHash('sha256');
let count = 0;
while (count < calls) {
  const m = Math.min(per, calls - count);
  for (let i = 0; i < m; i++) codec.encode(call(), buf, i * codec.bytes);
  const payload = buf.subarray(0, m * codec.bytes);
  h.update(payload);
  out(frame(FRAME.D, payload));
  count += m;
}
out(jsonFrame(FRAME.T, { count, payload_sha256: h.digest('hex'), src_after: srcManifest(ROOT).sha256 }));
