#!/usr/bin/env node
// A6 calibration of the 26 wave-1 EBC entries (CTO batch J, G-56): THE wave-1 statistic module, fed the
// labkit AES-256-CTR reference stream by wave1-source.mjs. VERIFICATION, not a counted evidence run: no
// battery tool, evidence gate CLOSED. Resumable per entry (<run-dir>/entry-NN.json, atomic, with digests).
// Usage: node verification/calibration/wave1-calibrate.mjs [--entries i,j] [--reps R] [--run-dir D] [--out F]
import { Worker, isMainThread, parentPort } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ENTRIES, STATISTIC as S, mCal, replicate, urnsPerRep } from './wave1-source.mjs';
import { ADAPTER_ID, KEY_HEX } from '../labkit/aes-ctr-ref.mjs';

const SELF = fileURLToPath(import.meta.url);
if (!isMainThread) {
  parentPort.on('message', ({ ei, r0, r1, M, map, cells }) => {
    const e = ENTRIES[ei]; const lumped = { map, cells };
    const out = [];
    for (let rep = r0; rep < r1; rep++) out.push({ rep, ...replicate(e, rep, M, lumped) });
    parentPort.postMessage({ ei, out, fallbacks: S.lehmerStats.fallbacks });
  });
} else {
  const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
  const R = Number(arg('--reps', S.A6.R));
  const which = arg('--entries', null);
  const idx = which ? which.split(',').map(Number) : ENTRIES.map((_, i) => i);
  const outFile = arg('--out', fileURLToPath(new URL('./wave1-results-j.json', import.meta.url)));
  const runDir = arg('--run-dir', '/workspace/rng-backup/calibration-run-j');
  mkdirSync(runDir, { recursive: true });
  const log = (m) => appendFileSync(join(runDir, 'progress.log'), `${new Date().toISOString()} ${m}\n`);
  const sha = (f) => createHash('sha256').update(readFileSync(new URL(f, import.meta.url))).digest('hex');
  const digests = { adapter: sha('../labkit/aes-ctr-ref.mjs'), statistic: sha('../statistic/wave1-statistic.mjs'), 'wave1-source.mjs': sha('./wave1-source.mjs'), 'wave1-calibrate.mjs': sha('./wave1-calibrate.mjs'), R };
  const nW = Math.max(1, Math.min(availableParallelism(), 8));
  const CH = 25;
  const workers = Array.from({ length: nW }, () => new Worker(SELF));
  const runEntry = (ei, M, lumped) => new Promise((done, fail) => {
    const tasks = []; for (let r = 0; r < R; r += CH) tasks.push({ ei, r0: r, r1: Math.min(R, r + CH), M, map: lumped.map, cells: lumped.cells });
    const out = []; let next = 0, pending = 0, fb = 0;
    const finish = () => { for (const w of workers) { w.removeAllListeners('message'); w.off('error', fail); } done({ out, fb }); };
    const feed = (wk) => { if (next < tasks.length) { pending += 1; wk.postMessage(tasks[next++]); } else if (pending === 0) finish(); };
    for (const wk of workers) {
      wk.on('message', (m) => { out.push(...m.out); fb = Math.max(fb, 0) + m.fallbacks; pending -= 1; feed(wk); });
      wk.once('error', fail);
    }
    for (const wk of workers) feed(wk);
  });
  const t0 = Date.now();
  const rows = [];
  for (const ei of idx) {
    const e = ENTRIES[ei];
    const f = join(runDir, `entry-${String(ei).padStart(2, '0')}.json`);
    if (existsSync(f)) {
      const prev = JSON.parse(readFileSync(f, 'utf8'));
      if (JSON.stringify(prev.digests) === JSON.stringify(digests)) { rows.push(prev.row); log(`entry ${ei} ${e.id}: reused ${prev.row.verdict}`); continue; }
      log(`entry ${ei} ${e.id}: stale file (digests differ), recomputing`);
    }
    const te = Date.now(); log(`entry ${ei} ${e.id}: start`);
    const M = mCal(e); const lumped = S.lumpExact(S.lawExact(e), M);
    const { out } = await runEntry(ei, M, lumped);
    const reps = out.sort((a, b) => a.rep - b.rep);
    const ps = reps.map((x) => x.p); const os = reps.map((x) => x.outcomes);
    const minOut = Math.min(...os);
    const v = S.a6Verdict(ps, minOut);
    const row = { id: e.id, stream: e.stream, reps: reps.length, M_cal: M, blocks_per_rep: e.kind === 'dup' ? M : null, urns_per_rep: urnsPerRep(e, M), cells: lumped.cells.length, df: lumped.cells.length - 1,
      minE: +(M * Math.min(...lumped.cells)).toFixed(3), outcomes_min: minOut, outcomes_max: Math.max(...os), outcomes_mean: os.reduce((a, x) => a + x, 0) / os.length,
      ks_D: +v.ks.D.toFixed(5), ks_p_asymptotic_stephens: +v.ks.p.toPrecision(4), flags_0_01: v.flags, verdict: v.pass ? 'PASS' : 'FAIL',
      pvalue_sha256: createHash('sha256').update(JSON.stringify(ps)).digest('hex'), pvalues: ps };
    writeFileSync(`${f}.tmp`, JSON.stringify({ digests, row }) + '\n');
    renameSync(`${f}.tmp`, f);
    rows.push(row);
    log(`entry ${ei} ${e.id}: done in ${Math.round((Date.now() - te) / 1000)} s: D ${row.ks_D} KS p ${row.ks_p_asymptotic_stephens} flags ${v.flags} ${row.verdict}`);
  }
  for (const w of workers) await w.terminate();
  const doc = {
    what: 'A6 calibration of the 26 wave-1 EBC entries through THE wave-1 statistic module (G-56) on the labkit reference stream (verification, NOT a counted evidence run; evidence gate stays CLOSED). Supersedes wave1-results.json (H2).',
    date: new Date().toISOString(), node: process.version, openssl: process.versions.openssl,
    statistic: { id: S.STATISTIC_ID, file: 'verification/statistic/wave1-statistic.mjs', sha256: digests.statistic },
    adapter: { id: ADAPTER_ID, key_hex: KEY_HEX, iv: 'BE32(stream) || BE32(rep) || 0^64; stream = entry index + 1, rep = 0..R-1 (the H2 IV set)', file_sha256: digests.adapter },
    harness_sha256: { 'wave1-source.mjs': digests['wave1-source.mjs'], 'wave1-calibrate.mjs': digests['wave1-calibrate.mjs'] },
    rule: { R, n: '>= 10^6 public-call outcomes per replication (R-A6n)', ks_alpha: S.A6.KS_ALPHA, D_crit_exact: 0.061462, flag_level: S.A6.FLAG, flag_interval: S.A6.FLAGS, ks_p: '[CL-3] asymptotic Kolmogorov series with the Stephens factor', laws: 'exact BigInt, exact §6.1 lumping' },
    seconds_this_invocation: Math.round((Date.now() - t0) / 1000), results: rows,
  };
  writeFileSync(outFile, JSON.stringify(doc) + '\n');
  log(`assembled ${rows.length} entries -> ${outFile}`);
  console.log(`${rows.filter((r) => r.verdict === 'PASS').length}/${rows.length} PASS -> ${outFile}`);
}
