// CTO commits H and J (HoQ addendum 1 A6-A8, G-56): labkit AES-256-CTR reference adapter, THE wave-1
// statistic module (shared by the evidence path and the calibration) and the calibration harness. Calibration is verification on the reference stream, not a counted evidence run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ref from '../verification/labkit/aes-ctr-ref.mjs';
import * as S from '../verification/statistic/wave1-statistic.mjs';
import * as Src from '../verification/calibration/wave1-source.mjs';
import * as Ev from '../verification/harness/wave1-evidence.mjs';
import { scanFile } from '../tools/ci/import-allowlist.mjs';
import { isUnderRepoSrc, defaultAllowedCallers } from '../tools/ci/entropy-backstop.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const sha = (rel) => createHash('sha256').update(readFileSync(join(ROOT, rel))).digest('hex');

test('labkit adapter: pinned digest, key and NIST SP 800-38A F.5.5 CTR-AES256 KAT', () => {
  assert.equal(sha('verification/labkit/aes-ctr-ref.mjs'), 'ae7a25d3d2a2529c746a6660af65efb816425786eb92cdcf546c8b793d0cc956');
  assert.equal(ref.KEY_HEX, createHash('sha256').update('open-rng-engine labkit reference AES-256-CTR key v1').digest('hex'));
  const k = ref.NIST_F55;
  assert.equal(ref.aesCtr(k.key, Buffer.from(k.iv, 'hex'), Buffer.from(k.plaintext, 'hex')).toString('hex'), k.ciphertext);
});

test('labkit adapter: own KAT vectors (keystream words, 1 MiB digest, below())', () => {
  assert.deepEqual(ref.selfKat(), {
    first8: [740981066, 2562251472, 3131492374, 232516785, 3435534316, 501044322, 176904737, 798519875],
    mib: '7988cc4e88d358f543bd9c841a968cb1874b4d7bd4b1ec3fda7456eda05279cb',
    below54: [26, 39, 51, 9, 14, 39, 2, 47, 19, 27],
    big: [1163318028, 128789884501595, 2135996307],
  });
});

test('labkit adapter and the wave-1 statistic stay outside src: rule 27 refuses a src import; no OS entropy', () => {
  for (const spec of ['../verification/labkit/aes-ctr-ref.mjs', '../verification/labkit/aes-ctr-ref.ts', '../verification/statistic/wave1-statistic.mjs', '../verification/calibration/wave1-source.mjs']) {
    const r = scanFile('src/zz-labkit.ts', `import { x } from '${spec}';\nexport const y = x;\n`);
    assert.ok(r.hits.some((h) => /rule27-specifier-not-allowed/.test(h)), spec);
  }
  assert.equal(isUnderRepoSrc(join(ROOT, 'src/index.ts')), true);
  assert.equal(isUnderRepoSrc(join(ROOT, 'verification/labkit/aes-ctr-ref.mjs')), false);
  assert.equal(JSON.stringify(defaultAllowedCallers()).includes('labkit'), false);
  for (const f of ['verification/labkit/aes-ctr-ref.mjs', 'verification/statistic/wave1-statistic.mjs', 'verification/calibration/wave1-source.mjs', 'verification/harness/wave1-evidence.mjs']) {
    assert.doesNotMatch(readFileSync(join(ROOT, f), 'utf8'), /from '\.\.\/\.\.\/src\/|randomBytes|randomFill|getRandomValues|Math\.random/);
  }
  assert.doesNotMatch(readFileSync(join(ROOT, 'verification/statistic/wave1-statistic.mjs'), 'utf8'), /^import /m, 'the statistic imports nothing (no stream inside)');
});

// G-56 identity: the evidence path and the calibration run the SAME module and function objects.
test('G-56: one statistic module, bound by identity on the evidence path and in the calibration', async () => {
  assert.equal(Ev.STATISTIC, Src.STATISTIC);
  const again = await import('../verification/statistic/wave1-statistic.mjs');
  assert.equal(Ev.STATISTIC, again);
  for (const fn of ['lawExact', 'lumpExact', 'observe', 'histogram', 'pearson', 'chi2sf', 'lehmerTop20', 'a6Verdict', 'ksUniform']) {
    assert.equal(typeof S[fn], 'function', fn);
    assert.equal(Ev.STATISTIC[fn], S[fn], fn); assert.equal(Src.STATISTIC[fn], S[fn], fn);
  }
  assert.match(readFileSync(join(ROOT, 'verification/calibration/wave1-calibrate.mjs'), 'utf8'), /from '\.\/wave1-source\.mjs'/);
  assert.match(readFileSync(join(ROOT, 'verification/calibration/wave1-source.mjs'), 'utf8'), /import \* as S from '\.\.\/statistic\/wave1-statistic\.mjs'/);
  // Same outcomes -> same statistic: the reference stream fed directly, and the same outcomes as records.
  const e = Src.ENTRIES[0]; const M = 200; const lu = S.lumpExact(S.lawExact(e), M);
  const direct = Src.replicate(e, 7, M, lu);
  const s = new ref.RefStream(e.stream, 7); const rec = []; const src = Src.refSource(e, s);
  const tap = () => { const v = src(); rec.push(v); return v; };
  const h = S.histogram(e, M, tap, lu.map.length);
  const viaRecords = Ev.statisticFromRecords(e, rec, M);
  assert.equal(viaRecords.x2, direct.x2); assert.equal(viaRecords.p, direct.p); assert.equal(viaRecords.unread, 0); assert.equal(h.outcomes, direct.outcomes);
  assert.throws(() => Ev.evidenceStatistic(e.id, { records: rec }, M), /G-54/);
});

const perms = (a) => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));

test('exact laws: brute-force enumeration (coupon d=2,3,4; duplicates m=3 b=5; adjacency 2x3, 3x2) and inclusion-exclusion', () => {
  const c2 = S.couponLawExact(2); for (let k = 2; k < 12; k++) assert.equal(c2.num[k - 2] * 2n ** BigInt(k - 1), c2.den, `coupon d=2 T=${k}`);
  for (const d of [3, 4]) {
    const c = S.couponLawExact(d);
    for (let t = d; t <= 9; t++) {
      let n = 0n; for (let x = 0; x < d ** t; x++) { const st = new Set(); let v = x, T = 0; for (let i = 0; i < t; i++) { st.add(v % d); v = Math.floor(v / d); if (st.size === d) { T = i + 1; break; } } if (T === t) n += 1n; }
      assert.equal(c.num[t - d] * BigInt(d) ** BigInt(t), n * c.den, `coupon d=${d} T=${t}`);
      // inclusion-exclusion: P(T <= t) = sum_j (-1)^j C(d,j) ((d-j)/d)^t
      let ie = 0n; for (let j = 0; j <= d; j++) { let C = 1n; for (let q = 0; q < j; q++) C = (C * BigInt(d - q)) / BigInt(q + 1); ie += (j % 2 ? -1n : 1n) * C * BigInt(d - j) ** BigInt(t); }
      let cum = 0n; for (let k = 0; k <= t - d; k++) cum += c.num[k];
      assert.equal(cum * BigInt(d) ** BigInt(t), ie * c.den, `coupon d=${d} P(T<=${t})`);
    }
  }
  const dl = S.dupLawExact(3, 5); const h = new Array(6).fill(0n);
  for (let x = 0; x < 3 ** 5; x++) { const st = new Set(); let v = x, C = 0; for (let i = 0; i < 5; i++) { if (st.has(v % 3)) C += 1; else st.add(v % 3); v = Math.floor(v / 3); } h[C] += 1n; }
  assert.equal(dl.den, 243n);
  for (let c = 0; c <= 4; c++) assert.equal(dl.num[c] ?? 0n, h[c], `dup C=${c}`);
  for (const [Lb, c] of [[2, 3], [3, 2]]) {
    const law = S.adjacencyLawExact(Lb, c); const deck = Array.from({ length: Lb * c }, (_, i) => Math.floor(i / c));
    const hh = new Map(); for (const p of perms(deck.map((_, i) => i))) { let X = 0; for (let i = 1; i < p.length; i++) if (deck[p[i]] === deck[p[i - 1]]) X += 1; hh.set(X, (hh.get(X) ?? 0n) + 1n); }
    for (const [X, n] of hh) assert.equal(law.num[X], n, `adjacency ${Lb}x${c} X=${X}`);
  }
});

test('exact lumping at M_cal reproduces the calibrated cell counts (all entries but d=641, which takes ~2 min)', () => {
  const cells = [17, 54, 246, 308, 438, 27, 349, 251, 315, null, 349, 308, 12, 10, 10, 10, 12, 10, 12, 10, 10, 10, 12, 12, 27, 14];
  const mcal = [500000, 166667, 27028, 19231, 10000, 333334, 15625, 26316, 18519, null, 15625, 19231, 200, 200, 400, 400, 200, 200, 245, 400, 400, 200, 245, 245, 1000000, 1000000];
  Src.ENTRIES.forEach((e, i) => {
    if (cells[i] === null) return;
    const M = Src.mCal(e); assert.equal(M, mcal[i], e.id);
    const lu = S.lumpExact(S.lawExact(e), M); assert.equal(lu.cells.length, cells[i], e.id);
    assert.ok(lu.cellNum.every((x) => BigInt(M) * x >= 5n * lu.den), e.id);
    assert.ok(Math.abs(lu.cells.reduce((a, x) => a + x, 0) - 1) < 1e-12, e.id);
  });
  // §6.1 threshold is 5, exactly: a cell with M*p = 5 stays, M*p just below 5 is merged.
  const law = { num: [5n, 990n, 5n], den: 1000n };
  assert.equal(S.lumpExact(law, 1000).cells.length, 3);
  assert.equal(S.lumpExact({ num: [4n, 992n, 4n], den: 1000n }, 1000).cells.length, 1);
});

test('reductions: duplicates count collisions within a block only; coupon and adjacency on crafted outcomes', () => {
  const e = { id: 'x', kind: 'dup', min: 0, r: 2, dd: 2, u: 1, b: 3, m: 2 };
  const seq = [0, 1, 0, 1, 0, 1]; let i = 0; const next = () => seq[i++];
  assert.deepEqual([S.observe(e, next).k, S.observe(e, next).k], [1, 1]);
  const c = { id: 'y', kind: 'coupon', min: 1, r: 6, d: 3 }; const s2 = [1, 2, 1, 6, 4]; let j = 0;
  assert.deepEqual(S.observe(c, () => s2[j++]), { k: 2, outcomes: 5 }); // units 0,0,0,2,1
  const a = S.ENTRIES.find((x) => x.label === 'mod4'); const p = Array.from({ length: 52 }, (_, k) => k);
  assert.equal(S.observe(a, () => p).k, 0);
  const q = Array.from({ length: 52 }, (_, k) => (k % 13) * 4 + Math.floor(k / 13));
  assert.equal(S.observe(a, () => q).k, 48);
});

test('A6 rule: two-sided KS with the Stephens factor, flag interval [2,22], outcome floor', () => {
  const ps = Array.from({ length: 1000 }, (_, i) => Math.min(1, (i + 0.5) / 1000 + (i < 500 ? 0.03 : 0)));
  const k = S.ksUniform(ps); assert.ok(Math.abs(k.D - 0.0305) < 1e-12); assert.ok(Math.abs(k.p - 0.3055863631963197) < 1e-12);
  const grid = Array.from({ length: 1000 }, (_, i) => (i + 0.5) / 1000);
  assert.equal(S.a6Verdict(grid, 1e6).pass, true);
  assert.equal(S.a6Verdict(grid, 1e6 - 1).pass, false);
  const one = grid.map((x) => (x < 0.01 && x > 0.001 ? 0.0105 : x)); assert.equal(S.a6Verdict(one, 1e6).flags, 1); assert.equal(S.a6Verdict(one, 1e6).pass, false);
  const many = grid.map((x, i) => (i < 23 ? x / 100 : x)); assert.equal(S.a6Verdict(many, 1e6).flags, 23); assert.equal(S.a6Verdict(many, 1e6).pass, false);
  assert.equal(S.a6Verdict(grid.map(() => 0.5), 1e6).pass, false);
  assert.ok(Math.abs(S.chi2sf(30.943101458355866, 7) - 0.01 / 157) < 1e-12);
});

test('Lehmer top-20 (exact) against the BigInt rank; lazy shuffle equals a full forward Fisher-Yates', () => {
  const F = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };
  for (let i = 0; i < 300; i++) {
    const s = new ref.RefStream(99, i); const a = Array.from({ length: 52 }, (_, k) => k);
    for (let j = 0; j < 51; j++) { const r = j + s.below(52 - j); [a[j], a[r]] = [a[r], a[j]]; }
    const lz = Src.lazyShuffle(new ref.RefStream(99, i));
    assert.equal(S.lehmerTop20(lz), S.lehmerTop20(a));
    const lz2 = Src.lazyShuffle(new ref.RefStream(99, i)); assert.deepEqual(Array.from({ length: 52 }, (_, k) => lz2.card(k)), a);
    let rank = 0n; for (let j = 0; j < 52; j++) { let d = 0; for (let k = j + 1; k < 52; k++) if (a[k] < a[j]) d += 1; rank += BigInt(d) * F(51 - j); }
    assert.equal(S.lehmerTop20(a), Number((rank * 1048576n) / F(52)));
  }
});

// H2 results (superseded by the J run, kept): internally consistent as committed.
const RESULTS = join(ROOT, 'verification/calibration/wave1-results.json');
test('H2 calibration results file (superseded, kept): 26 entries, R = 1000, n >= 10^6, verdicts follow the A6 rule', () => {
  assert.ok(existsSync(RESULTS), 'results file committed in H2');
  const doc = JSON.parse(readFileSync(RESULTS, 'utf8'));
  assert.equal(doc.results.length, 26);
  assert.deepEqual(doc.results.map((r) => r.id).sort(), S.ENTRIES.map((e) => e.id).sort());
  assert.equal(doc.adapter.key_hex, ref.KEY_HEX);
  assert.equal(doc.adapter.file_sha256, sha('verification/labkit/aes-ctr-ref.mjs'));
  for (const r of doc.results) {
    assert.ok(r.reps >= 1000 && r.minOutcomes >= 1e6, r.id);
    const o = r.outcomes_per_rep;
    assert.ok(o && o.meets_n_1e6 === true && (o.exact ?? o.min) >= 1e6 && (o.exact ?? o.min) === r.minOutcomes, r.id);
    const pass = r.ks_p >= 0.001 && r.flags_0_01 >= 2 && r.flags_0_01 <= 22;
    assert.equal(r.verdict, pass ? 'PASS' : 'FAIL', r.id);
  }
});

// G-59: the H2 per-replication p-values are committed and authenticate the H2 rows.
test('H2 per-rep p-values committed (G-59) and match the H2 digests; H2 marked superseded', () => {
  const h2 = JSON.parse(readFileSync(RESULTS, 'utf8'));
  const pv = JSON.parse(readFileSync(join(ROOT, 'verification/calibration/wave1-h2-pvalues.json'), 'utf8'));
  assert.equal(h2.superseded.by, 'verification/calibration/wave1-results-j.json');
  pv.entries.forEach((x, i) => {
    assert.equal(x.id, h2.results[i].id);
    assert.equal(createHash('sha256').update(JSON.stringify(x.pvalues)).digest('hex'), h2.results[i].pvalue_sha256, x.id);
  });
});

// J3: the calibration of THE statistic. Digests bound to the current files (G-58), verdicts recomputed from
// the committed p-values with the module's own A6 rule, outcomes and urns per replication (R-A6n).
const RJ = join(ROOT, 'verification/calibration/wave1-results-j.json');
test('J calibration results: statistic and harness digests equal the current files; verdicts recomputed from the committed p-values', () => {
  const doc = JSON.parse(readFileSync(RJ, 'utf8'));
  assert.equal(doc.statistic.id, S.STATISTIC_ID);
  assert.equal(doc.statistic.sha256, sha('verification/statistic/wave1-statistic.mjs'));
  assert.equal(doc.harness_sha256['wave1-source.mjs'], sha('verification/calibration/wave1-source.mjs'));
  assert.equal(doc.harness_sha256['wave1-calibrate.mjs'], sha('verification/calibration/wave1-calibrate.mjs'));
  assert.equal(doc.adapter.file_sha256, sha('verification/labkit/aes-ctr-ref.mjs'));
  assert.deepEqual(doc.results.map((r) => r.id), Src.ENTRIES.map((e) => e.id));
  doc.results.forEach((r, i) => {
    const e = Src.ENTRIES[i];
    assert.equal(r.stream, e.stream); assert.equal(r.reps, 1000); assert.equal(r.pvalues.length, 1000);
    assert.equal(createHash('sha256').update(JSON.stringify(r.pvalues)).digest('hex'), r.pvalue_sha256, r.id);
    const v = S.a6Verdict(r.pvalues, r.outcomes_min);
    assert.equal(+v.ks.D.toFixed(5), r.ks_D, r.id); assert.equal(+v.ks.p.toPrecision(4), r.ks_p_asymptotic_stephens, r.id);
    assert.equal(v.flags, r.flags_0_01, r.id); assert.equal(v.pass ? 'PASS' : 'FAIL', r.verdict, r.id);
    assert.ok(r.outcomes_min >= 1e6, r.id);
    if (e.kind === 'dup') { assert.equal(r.outcomes_min, r.M_cal * e.b * e.u); assert.equal(r.urns_per_rep, r.M_cal * e.b); assert.equal(r.blocks_per_rep, r.M_cal); }
    if (e.kind === 'adj') assert.equal(r.outcomes_min, r.M_cal);
    if (e.kind === 'coupon') assert.ok(r.outcomes_min >= r.M_cal * e.d);
  });
});

const REFSTREAM_3MIB = '3005b6c4e6b191c0729502e5aab3dde8bb39ca6f50496c24e1f8fa88ae0695c0';
// G-58 (HM-37): RefStream itself across refills, derived independently from aesCtr() over 3 MiB, plus a pinned digest.
test('labkit RefStream: multi-chunk keystream equals one-shot AES-256-CTR (no restart at 1 MiB refills)', () => {
  const s = new ref.RefStream(0, 0); const n = (3 << 20) >>> 2; const w = new Uint32Array(n);
  for (let i = 0; i < n; i++) w[i] = s.u32();
  const got = createHash('sha256').update(Buffer.from(w.buffer)).digest('hex');
  const want = createHash('sha256').update(ref.aesCtr(ref.KEY_HEX, ref.ivFor(0, 0), Buffer.alloc(3 << 20))).digest('hex');
  assert.equal(got, want); assert.equal(s.words, n);
  assert.equal(got, REFSTREAM_3MIB);
});

// G-58 (HM-35): below() rejection limits at the boundary, with scripted words.
test('labkit below(): rejection limit exact (u = lim rejected, lim - 1 accepted) for every range branch', () => {
  const T = 2 ** 32;
  const run = (r, words) => { let i = 0; const f = { u32: () => { if (i >= words.length) throw new Error('drew past script'); return words[i++]; } }; const v = ref.RefStream.prototype.below.call(f, r); return [v, i]; };
  for (const r of [2, 6, 7, 37, 38, 52, 53, 54, 100, 2 ** 31 + 1]) {
    const lim = T - (T % r);
    assert.deepEqual(run(r, [lim, lim - 1]), [(lim - 1) % r, 2], `r=${r} u=lim must be rejected`);
    assert.deepEqual(run(r, [lim - 1]), [(lim - 1) % r, 1], `r=${r} u=lim-1 accepted`);
    if (T % r !== 0) assert.deepEqual(run(r, [T - 1, 0]), [0, 2], `r=${r} u=2^32-1 rejected`);
  }
  assert.deepEqual(run(T, [T - 1]), [T - 1, 1]);
  assert.deepEqual(run(T + 1, [1, 1, 1, 0]), [T, 4], '2^32+1: x = r rejected, x = 2^32 accepted');
  assert.deepEqual(run(T + 1, [0xfffffffe, 5]), [5, 2], '2^32+1: low bit of the first word only');
  assert.deepEqual(run(2 ** 48, [0x12345, 7]), [0x2345 * T + 7, 2]);
});

// G-58: a small fixed-seed re-run of the calibration path itself (lawExact, lumpExact, the reference source,
// histogram, pearson): 3 entries x R = 20 reproduce the committed J p-values exactly, then the A6 rule.
test('calibration fixture: 3 entries x 20 reps re-run reproduce the committed J p-values', () => {
  const doc = JSON.parse(readFileSync(RJ, 'utf8'));
  for (const ei of [0, 16, 25]) {
    const e = Src.ENTRIES[ei]; const M = Src.mCal(e); const lumped = S.lumpExact(S.lawExact(e), M);
    assert.equal(M, doc.results[ei].M_cal); assert.equal(lumped.cells.length, doc.results[ei].cells);
    const ps = []; for (let rep = 0; rep < 20; rep++) { const r = Src.replicate(e, rep, M, lumped); ps.push(r.p); assert.equal(r.outcomes >= 1e6, true); }
    assert.deepEqual(ps, doc.results[ei].pvalues.slice(0, 20), e.id);
  }
});
