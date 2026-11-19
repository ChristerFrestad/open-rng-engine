#!/usr/bin/env node
// A6 calibration of the 26 wave-1 EBC entries on the labkit AES-256-CTR reference stream (CTO commit H).
// This is VERIFICATION, not a counted evidence run: it starts no battery tool and the evidence gate stays
// closed. Usage: node verification/calibration/wave1-calibrate.mjs [--entries i,j,...] [--reps R] [--out F]
//   [--run-dir D] (default /workspace/rng-backup/calibration-run; per-entry files, resumable)
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ENTRIES, R_CAL, mCal, lawOf, replicate, lehmerStats } from './wave1-entries.mjs';
import { lump, pearsonP, ksUniform } from './laws.mjs';
import { ADAPTER_ID, KEY_HEX } from '../labkit/aes-ctr-ref.mjs';

const SELF = fileURLToPath(import.meta.url);
const prep = (e) => { const law = lawOf(e); const M = mCal(e); const lu = lump(law.p, M); return { law, M, lu }; };

if (!isMainThread) {
  const cache = new Map();
  parentPort.on('message', ({ ei, r0, r1 }) => {
    const e = ENTRIES[ei];
    if (!cache.has(ei)) cache.set(ei, prep(e));
    const { law, M, lu } = cache.get(ei);
    const out = [];
    for (let rep = r0; rep < r1; rep++) {
      const { h, outcomes, words } = replicate(e, rep, M, law.p.length);
      const counts = new Float64Array(lu.cells.length);
      for (let i = 0; i < h.length; i++) counts[lu.map[i]] += h[i];
      const { x2, p } = pearsonP(counts, lu.cells, M);
      out.push({ rep, x2, p, outcomes, words });
    }
    parentPort.postMessage({ ei, out, fallbacks: lehmerStats.fallbacks });
  });
} else {
  // Resumable per entry: each finished entry is written atomically to <run-dir>/entry-NN.json (with the
  // harness and adapter digests); a rerun skips entries whose file matches those digests, so an
  // interruption loses at most the entry in progress. The results file is assembled when all are present.
  const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
  const R = Number(arg('--reps', R_CAL));
  const which = arg('--entries', null);
  const idx = which ? which.split(',').map(Number) : ENTRIES.map((_, i) => i);
  const outFile = arg('--out', fileURLToPath(new URL('./wave1-results.json', import.meta.url)));
  const runDir = arg('--run-dir', '/workspace/rng-backup/calibration-run');
  mkdirSync(runDir, { recursive: true });
  const log = (m) => appendFileSync(join(runDir, 'progress.log'), `${new Date().toISOString()} ${m}\n`);
  const sha = (f) => createHash('sha256').update(readFileSync(new URL(f, import.meta.url))).digest('hex');
  const digests = { adapter: sha('../labkit/aes-ctr-ref.mjs'), 'laws.mjs': sha('./laws.mjs'), 'wave1-entries.mjs': sha('./wave1-entries.mjs'), 'wave1-calibrate.mjs': sha('./wave1-calibrate.mjs'), R };
  const nW = Math.max(1, Math.min(availableParallelism(), 8));
  const CH = 25;
  const workers = Array.from({ length: nW }, () => new Worker(SELF));
  const runEntry = (ei) => new Promise((done, fail) => {
    const tasks = []; for (let r = 0; r < R; r += CH) tasks.push({ ei, r0: r, r1: Math.min(R, r + CH) });
    const out = []; let next = 0, pending = 0, fb = 0;
    const feed = (wk) => { if (next < tasks.length) { pending += 1; wk.postMessage(tasks[next++]); } else if (pending === 0) { for (const w of workers) w.removeAllListeners('message'); done({ out, fb }); } };
    for (const wk of workers) {
      wk.removeAllListeners('message');
      wk.on('message', (m) => { out.push(...m.out); fb += m.fallbacks; pending -= 1; feed(wk); });
      wk.once('error', fail);
    }
    for (const wk of workers) feed(wk);
  });
  const t0 = Date.now();
  const rows = []; let fallbacks = 0;
  for (const ei of idx) {
    const e = ENTRIES[ei];
    const f = join(runDir, `entry-${String(ei).padStart(2, '0')}.json`);
    if (existsSync(f)) {
      const prev = JSON.parse(readFileSync(f, 'utf8'));
      if (JSON.stringify(prev.digests) === JSON.stringify(digests)) { rows.push(prev.row); fallbacks += prev.fallbacks; log(`entry ${ei} ${e.id}: reused ${prev.row.verdict}`); continue; }
      log(`entry ${ei} ${e.id}: stale file (digests differ), recomputing`);
    }
    const te = Date.now(); log(`entry ${ei} ${e.id}: start`);
    const { M, lu } = prep(e);
    const { out, fb } = await runEntry(ei);
    const reps = out.sort((a, b) => a.rep - b.rep);
    const ps = reps.map((x) => x.p);
    const ks = ksUniform(ps); const flags = ps.filter((p) => p < 0.01).length;
    const minOut = Math.min(...reps.map((x) => x.outcomes));
    const pass = ks.p >= 0.001 && flags >= 2 && flags <= 22 && reps.length >= 1000 && minOut >= 1e6;
    const row = { id: e.id, stream: e.stream, reps: reps.length, M_cal: M, cells: lu.cells.length, df: lu.cells.length - 1, minE: +(M * Math.min(...lu.cells)).toFixed(3), minOutcomes: minOut, ks_D: +ks.D.toFixed(5), ks_p: +ks.p.toPrecision(4), flags_0_01: flags, verdict: pass ? 'PASS' : 'FAIL', pvalue_sha256: createHash('sha256').update(JSON.stringify(ps)).digest('hex') };
    writeFileSync(`${f}.tmp`, JSON.stringify({ digests, row, fallbacks: fb, pvalues: ps }) + '\n');
    renameSync(`${f}.tmp`, f);
    rows.push(row); fallbacks += fb;
    log(`entry ${ei} ${e.id}: done in ${Math.round((Date.now() - te) / 1000)} s: D ${row.ks_D} KS p ${row.ks_p} flags ${flags} ${row.verdict}`);
  }
  for (const w of workers) await w.terminate();
  const doc = {
    what: 'A6 calibration of wave-1 EBC entries on the labkit reference stream (verification, NOT a counted evidence run; evidence gate stays CLOSED)',
    date: new Date().toISOString(), node: process.version, openssl: process.versions.openssl,
    adapter: { id: ADAPTER_ID, key_hex: KEY_HEX, iv: 'BE32(stream) || BE32(rep) || 0^64; stream = entry stream index below, rep = 0..R-1', file_sha256: digests.adapter },
    harness_sha256: { 'laws.mjs': digests['laws.mjs'], 'wave1-entries.mjs': digests['wave1-entries.mjs'], 'wave1-calibrate.mjs': digests['wave1-calibrate.mjs'] },
    rule: { R, n_per_rep: '>= 10^6 outcomes: M_cal = max(ceil(10^6 / min outcomes per observation), 200) (adjacency: 10^6 shuffles), doubled until the lumped table has >= 10 cells', ks_alpha: 0.001, D_crit_A6: 0.0617, flag_level: 0.01, flag_interval: [2, 22], ks_p: '[CL-3] asymptotic Kolmogorov series with the (sqrt(R)+0.12+0.11/sqrt(R)) factor' },
    lehmer_prefix_fallbacks: fallbacks, seconds_this_invocation: Math.round((Date.now() - t0) / 1000), results: rows,
  };
  writeFileSync(outFile, JSON.stringify(doc, null, 1) + '\n');
  log(`assembled ${rows.length} entries -> ${outFile}`);
  console.log(`${rows.filter((r) => r.verdict === 'PASS').length}/${rows.length} PASS -> ${outFile}`);
  for (const r of rows) console.log(`${r.id} | M_cal ${r.M_cal} | cells ${r.cells} | min E ${r.minE} | D ${r.ks_D} | KS p ${r.ks_p} | flags ${r.flags_0_01} | ${r.verdict}`);
}
