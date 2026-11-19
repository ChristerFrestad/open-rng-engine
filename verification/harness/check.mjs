// Evidence-harness precondition checks and their self-test (mutants). Decision rule v1 (FROZEN 5d09c75a).
//   default:     rule 15 pins (answer file, driver, archives vs the frozen text) and the M-153 floor on the
//                157-entry K list (rule 8 / rule 15 TODO-CTO-1). Exit 1 on any finding.
//   --self-test: synthetic fixtures for rule 8 (M-153), rule 15 / 17(ii) pins and rule 17(i) counts, then
//                every mutant in MUTANTS; exit 1 unless all fixtures behave, every mutant is killed and no
//                patch failed. No evidence data is read or produced.
// Rule 8 df table (df-table.mjs): integrity is a PH0 finding; readiness (every df-null K entry has a df)
// is reported only and blocks the evidence-run entry point (evidence-entry.mjs), not check:ph0.
import { readFileSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, '..', '..');
const K_TESTS = 'verification/k-tests-v1.1.json';

export function loadKTests(root = ROOT) {
  return JSON.parse(readFileSync(join(root, K_TESTS), 'utf8')).tests;
}

async function load(dir) {
  const imp = (f) => import(pathToFileURL(join(dir, f)).href + `?t=${Date.now()}${Math.random()}`);
  return { pins: await imp('pins.mjs'), floor: await imp('n-floor.mjs'), counts: await imp('counts.mjs'), df: await imp('df-table.mjs'), col: await imp('collector.mjs'), ev: await imp('evidence-entry.mjs') };
}

export async function runChecks(root = ROOT, mods) {
  const m = mods || (await load(HERE));
  const kTests = loadKTests(root);
  const kBytes = readFileSync(join(root, K_TESTS));
  const kSha = m.pins.sha256(kBytes);
  const findings = [...m.pins.checkHarnessPins(root), ...m.pins.checkArchivePinsAgainstFrozen(root), ...m.df.checkDfTable(kTests, { kTestsSha256: kSha }), ...m.ev.runnerContractFindings(root)];
  if (kTests.length !== 157) findings.push(`K list has ${kTests.length} entries, expected 157 (rule 8 K′)`);
  const plans = kTests.map((t) => ({ id: t.id, n: m.floor.N_MIN, unit: m.floor.expectedUnit(t), counter: m.floor.COUNTER_PER_PUBLIC_CALL }));
  findings.push(...m.floor.checkRunPlans(plans, kTests));
  return findings;
}

export async function readiness(root = ROOT, mods) {
  const m = mods || (await load(HERE));
  return m.df.dfReadiness(loadKTests(root));
}

// ---- synthetic fixtures (deterministic numbers, never tool output) ----
function stsSeq(counts, over = {}) {
  const s = {};
  for (const [k, n] of Object.entries(counts)) s[k] = Array.from({ length: n }, (_, i) => (i + 0.5) / (n + 1));
  return Object.assign(s, over);
}
function stsRun(counts, nseq = 1000, edit) {
  // Distinct sequences (EG-2): each sequence's p-values are shifted by its index.
  const seqs = Array.from({ length: nseq }, (_, j) => {
    const s = stsSeq(counts);
    s.Frequency = [(j + 0.5) / (nseq + 1)];
    return s;
  });
  if (edit) edit(seqs);
  return seqs;
}
let NAMES = [];
function tu01Text(stream, n, { battery = 'BigCrush', head = n, badP, names = NAMES, off = stream === 'u32' ? 0.25 : 0 } = {}) {
  const rows = Array.from({ length: n }, (_, i) => `${battery}\t${stream}\t${i}\t${names[i] ?? `syn_${i}`}\t${i === badP ? -1 : (i + 0.5 + off) / (n + 1)}`);
  return [`# tu01-driver v1\tbattery=${battery}\tstream=${stream}\tntests=${head}\twords=0`, ...rows].join('\n') + '\n';
}
let DH_ROWS = [];
const DH_EXCLUDED = ['diehard_opso', 'diehard_oqso', 'diehard_dna', 'diehard_sums'];
// Default: the pinned 114-row list in order. Options rebuild the old count-only edits on top of it.
function dhText({ counted = 110, excluded = DH_EXCLUDED, badP = false, rows } = {}) {
  const row = (name, ntup, p) => `${name.padStart(20)}|${String(ntup).padStart(4)}|       100|     100|${p.toFixed(8)}|  PASSED  `;
  const lines = ['#=============================================================================#', '        test_name   |ntup| tsamples |psamples|  p-value |Assessment'];
  let list = rows ?? DH_ROWS.map((r) => [r[0], r[1] ?? 0]);
  if (!rows) {
    const cnt = list.filter((r) => !DH_EXCLUDED.includes(r[0]));
    const ex = excluded.map((n) => [n, 0]);
    const c2 = cnt.slice(0, counted);
    for (let i = cnt.length; i < counted; i++) c2.push([`syn_counted_${i}`, 0]);
    list = [...ex, ...c2];
    if (counted === 110 && excluded === DH_EXCLUDED) list = DH_ROWS.map((r) => [r[0], r[1] ?? 0]);
  }
  list.forEach(([n, t], i) => lines.push(row(n, t, badP && i === 0 ? 1.5 : (i + 0.5) / (list.length + 1))));
  return lines.join('\n') + '\n';
}
const SHA_A = 'a'.repeat(64), SHA_B = 'b'.repeat(64);
// Pinned-list digests held here on their own (EG-2), so a changed list in counts.mjs is red.
const BIGCRUSH_NAMES_SHA256 = '02ddf54c9695d249c28eb2fa90ed04f0ace64494ebaf32ca7ea8cc22c60f448b';
const DIEHARDER_ROWS_SHA256 = '9c5f7a5d80dad768d213dff1034950353a90dfa6a4b8e263f9991a15786a61b3';

// EG-1: synthetic primitives over a deterministic LCG (no entropy), with an instrumented source that
// counts inner draws, tries, bytes and Lehmer digits the way a real source's byte log would.
function lcg(seed) { let x = seed >>> 0; return () => (x = (Math.imul(x, 1664525) + 1013904223) >>> 0); }
function synth(kTest, source) {
  const next = lcg(12345);
  const draw = (bound) => { // A.5.1-style masked rejection over 32-bit words; counts tries and 4 bytes per try
    let bits = 0; while ((1 << bits) < bound && bits < 31) bits++;
    for (;;) { source.tries += 1; source.bytes += 4; const v = bits === 0 ? 0 : next() >>> (32 - bits); if (v < bound) { source.draws += 1; return v; } }
  };
  const p = kTest.parameters || {};
  switch (kTest.primitive) {
    case 'randomInt': return () => p.min + draw(p.max - p.min);
    case 'weightedPick': { const len = p.length ?? p.weights.length; return () => draw(len); }
    case 'shuffle': return () => {
      const a = Array.from({ length: p.n ?? 52 }, (_, i) => i);
      for (let i = a.length - 1; i > 0; i--) { const j = draw(i + 1); [a[i], a[j]] = [a[j], a[i]]; }
      if (/Lehmer/.test(kTest.n_unit)) source.digits += a.length - 1;
      return a;
    };
    case 'sample': return () => {
      const a = Array.from({ length: p.n }, (_, i) => i); const out = [];
      for (let i = 0; i < p.k; i++) { const j = i + draw(p.n - i); [a[i], a[j]] = [a[j], a[i]]; out.push(a[i]); }
      return out;
    };
    default: throw new Error('no synthetic primitive');
  }
}
function collectorRun(C, kTest, n = 200) {
  const source = { draws: 0, tries: 0, bytes: 0, digits: 0 };
  const wit = C.witness(synth(kTest, source));
  const res = C.collect(kTest, wit.call, n, source);
  return { res, returns: wit.count(), source };
}

const STS_OK = { Frequency: 1, BlockFrequency: 1, CumulativeSums: 2, Runs: 1, LongestRun: 1, Rank: 1, FFT: 1, NonOverlappingTemplate: 148, OverlappingTemplate: 1, Universal: 1, ApproximateEntropy: 1, RandomExcursions: 8, RandomExcursionsVariant: 18, Serial: 2, LinearComplexity: 1 };

// Each case: [name, expectGreen, () => findings[]].
export function fixtureCases(m, root = ROOT) {
  const kTests = loadKTests(root);
  const F = m.floor;
  const id = (re) => kTests.find((t) => re.test(t.id)).id;
  const tupleId = kTests.find((t) => /tuple/.test(t.n_unit)).id;
  const plan = (over) => ({ id: id(/^randomInt\/chi2\/min-0-max-38$/), n: 1000000000, unit: F.UNIT_PUBLIC_CALL, counter: F.COUNTER_PER_PUBLIC_CALL, ...over });
  const one = (p) => { const r = F.checkPlan(p, kTests); return r.ok ? [] : [r.reason]; };
  const shuffle52 = id(/^shuffle\/.*n-52/);
  const sample805 = kTests.find((t) => t.primitive === 'sample').id;
  const goodC = () => ({ sts: stsRun(STS_OK), bigcrush: { raw: tu01Text('raw', 160), u32: tu01Text('u32', 160) }, bigcrushInputs: { raw: SHA_A, u32: SHA_B }, dieharder: dhText() });
  const withC = (edit) => { const c = goodC(); edit(c); return m.counts.checkFirstRunCounts(c); };
  const D = m.df;
  const dfCases = dfFixtureCases(D, kTests);
  NAMES = m.counts.BIGCRUSH_TEST_NAMES;
  DH_ROWS = m.counts.DIEHARDER_ROWS;
  const C = m.col;
  const kt = (re) => kTests.find((t) => re.test(t.id));
  const fam = {
    'randomInt r=38 (A.5.1 tries)': kt(/^randomInt\/chi2\/min-0-max-38$/),
    'shuffle 52 (Fisher-Yates steps)': kt(/^shuffle\/.*n-52/),
    'shuffle Lehmer-52 (digits)': kTests.find((t) => /Lehmer/.test(t.n_unit)),
    'sample 52/5 (index draws)': kTests.find((t) => t.primitive === 'sample' && t.parameters.k === 5),
    'sample k=20 (index draws)': kTests.find((t) => t.primitive === 'sample' && t.parameters.k === 20) ?? kTests.find((t) => t.primitive === 'sample'),
    'weightedPick W-A (tries, bytes)': kTests.find((t) => t.primitive === 'weightedPick' && !/tuple/.test(t.n_unit)),
    'randomInt ordered pair (tuples of 2)': kt(/^randomInt\/ordered-pair-chi2\//),
    'weightedPick five-call window (tuples of 5)': kt(/five-call-pair/),
  };
  const colCases = [];
  for (const [label, k] of Object.entries(fam)) {
    colCases.push([`EG-1 collector ${label}: n = records = witness returns / w, shapes ok`, true, () => {
      const { res, returns, source } = collectorRun(C, k);
      const f = C.checkCollected(res, k, returns, { floor: false });
      if (res.n !== 200) f.push(`collector n ${res.n} != 200 calls requested`);
      if (k.primitive === 'shuffle' && !(source.draws > res.n)) f.push('synthetic source did not log inner draws');
      if (k.primitive === 'randomInt' && !(source.tries > source.draws)) f.push('synthetic source logged no rejected tries');
      return f;
    }]);
  }
  const kS = fam['shuffle 52 (Fisher-Yates steps)'], kR = fam['randomInt r=38 (A.5.1 tries)'], kP = fam['randomInt ordered pair (tuples of 2)'];
  const kL = fam['shuffle Lehmer-52 (digits)'], kSa = fam['sample 52/5 (index draws)'], kW = fam['weightedPick W-A (tries, bytes)'];
  const bad = (k, edit) => { const { res, returns, source } = collectorRun(C, k); edit(res, source); return C.checkCollected(res, k, returns, { floor: false }); };
  colCases.push(
    ['EG-1 B4/B5 n counted per Fisher-Yates step', false, () => bad(kS, (r, s) => { r.n = s.draws; })],
    ['EG-1 B4 records are index draws', false, () => bad(kS, (r) => { r.records = r.records.flat(); r.n = r.records.length; })],
    ['EG-1 B6/B7 n counted per sampled index', false, () => bad(kSa, (r) => { r.records = r.records.flat(); r.n = r.records.length; })],
    ['EG-1 B8 n counted from tries', false, () => bad(kR, (r, s) => { r.n = s.tries; })],
    ['EG-1 B9/B11 n counted from bytes', false, () => bad(kW, (r, s) => { r.n = s.bytes; })],
    ['EG-1 B10 n counted as Lehmer digits', false, () => bad(kL, (r, s) => { r.n = s.digits; })],
    ['EG-1 B12 n counted as window values', false, () => bad(kP, (r) => { r.records = r.records.flat(); r.n = r.records.length; })],
    ['EG-1 n and records inflated together (witness disagrees)', false, () => bad(kR, (r) => { r.records = [...r.records, ...r.records]; r.n = r.records.length; })],
    ['EG-1 records dropped while n is kept (n != records)', false, () => bad(kR, (r) => { r.records = r.records.slice(0, 100); })],
    ['EG-1 a record that is not an outcome (out of range)', false, () => bad(kR, (r) => { r.records[3] = 999; })],
    ['EG-1 B1 floor at collection: 200 outcomes', false, () => { const { res, returns } = collectorRun(C, kR); return C.checkCollected(res, kR, returns); }],
    ['EG-1 window width from K: five-call windows are 5, pairs 2, plain 1', true, () => [
      ...need(C.windowWidth(fam['weightedPick five-call window (tuples of 5)']) === 5, 'five-call'),
      ...need(C.windowWidth(kP) === 2, 'pair'), ...need(C.windowWidth(kR) === 1, 'plain')]],
  );
  const egCases = [
    ['EG-2 BigCrush names list digest', true, () => need(m.pins.sha256(Buffer.from(JSON.stringify(m.counts.BIGCRUSH_TEST_NAMES))) === BIGCRUSH_NAMES_SHA256 && m.counts.BIGCRUSH_TEST_NAMES.length === 160, 'BigCrush names list changed')],
    ['EG-2 Dieharder rows list digest', true, () => need(m.pins.sha256(Buffer.from(JSON.stringify(m.counts.DIEHARDER_ROWS))) === DIEHARDER_ROWS_SHA256 && m.counts.DIEHARDER_ROWS.length === 114, 'Dieharder rows list changed')],
    ['EG-2 Dieharder a counted row duplicated and another missing (110 rows, wrong set)', false, () => withC((c) => {
      const l = DH_ROWS.map((r) => [r[0], r[1] ?? 0]); l[22] = l[21]; c.dieharder = dhText({ rows: l });
    })],
    ['EG-2 Dieharder rgb_bitdist ntup 3 twice, ntup 4 missing', false, () => withC((c) => {
      const l = DH_ROWS.map((r) => [r[0], r[1] ?? 0]); const i = l.findIndex((r) => r[0] === 'rgb_bitdist' && r[1] === 4); l[i] = [l[i][0], 3]; c.dieharder = dhText({ rows: l });
    })],
    ['EG-2 Dieharder two rows swapped', false, () => withC((c) => {
      const l = DH_ROWS.map((r) => [r[0], r[1] ?? 0]); [l[0], l[1]] = [l[1], l[0]]; c.dieharder = dhText({ rows: l });
    })],
    ['EG-2 Dieharder a renamed counted row', false, () => withC((c) => {
      const l = DH_ROWS.map((r) => [r[0], r[1] ?? 0]); l[0] = ['diehard_birthdayz', l[0][1]]; c.dieharder = dhText({ rows: l });
    })],
    ['EG-2 BigCrush raw rows with synthetic names', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 160, { names: [] }); })],
    ['EG-2 BigCrush raw two rows swapped', false, () => withC((c) => { const n = [...NAMES]; [n[0], n[2]] = [n[2], n[0]]; c.bigcrush.raw = tu01Text('raw', 160, { names: n }); })],
    ['EG-2 BigCrush u32 is a relabelled copy of raw (same p-values)', false, () => withC((c) => { c.bigcrush.u32 = tu01Text('u32', 160, { off: 0 }); })],
    ['EG-2 BigCrush u32 input sha = raw input sha', false, () => withC((c) => { c.bigcrushInputs = { raw: SHA_A, u32: SHA_A }; })],
    ['EG-2 BigCrush input shas missing', false, () => withC((c) => { delete c.bigcrushInputs; })],
    ['EG-2 STS one sequence duplicated', false, () => withC((c) => { c.sts[7] = JSON.parse(JSON.stringify(c.sts[6])); })],
    ['EG-2 STS 1000 identical sequences', false, () => withC((c) => { c.sts = c.sts.map(() => JSON.parse(JSON.stringify(c.sts[0]))); })],
  ];
  const E = m.ev;
  const rc = (t) => { const w = E.runnerContractText(t); return w ? [w] : []; };
  // Tool names are assembled so this file's own text is not a runner under the EG-3 scan.
  const [DH, TU, AS, PR, CO] = ['die' + 'harder', 'tu01' + '-driver', 'ass' + 'ess', 'RNG' + '_test', 'collector' + '.mjs'];
  const egCases3 = [
    ['EG-3 runner spawning dieharder without the guard is red', false, () => rc(`import { spawnSync } from 'node:child_process';\nspawnSync('${DH}', ['-a', '-Y', '0', '-g', '201']);\n`)],
    ['EG-3 runner calling the guard after spawning tu01-driver is red', false, () => rc(`execFileSync('./${TU}', ['BigCrush', 'raw', 'o.tsv']);\nassertEvidenceRunReady();\n`)],
    ['EG-3 runner importing the collector without the guard is red', false, () => rc(`import { collect } from './${CO}';\ncollect(k, f, 1e9);\n`)],
    ['EG-3 runner with the guard first is green', true, () => rc(`import { assertEvidenceRunReady } from './evidence-entry.mjs';\nassertEvidenceRunReady();\nspawnSync('${AS}', ['1000000']);\n`)],
    ['EG-3 runner through startEvidenceRun is green', true, () => rc(`startEvidenceRun(() => spawnSync('${PR}', ['stdin64']));\n`)],
    ['EG-3 tracked tree has no unguarded runner', true, () => E.runnerContractFindings(root)],
    ['EG-3 startEvidenceRun refuses while NOT-READY', false, () => { try { E.startEvidenceRun(() => 0, root); return []; } catch (e) { return [String(e.message)]; } }],
  ];
  return [
    ...egCases3,
    ...colCases,
    ...egCases,
    ...dfCases,
    // rule 15 / 17(ii) pins on the real tree
    ['pins: real tree green', true, () => [...m.pins.checkHarnessPins(root), ...m.pins.checkArchivePinsAgainstFrozen(root)]],
    // rule 8 / M-153
    ['M-153 G: all 157 K ids at n=10^9 in their unit', true, () => F.checkRunPlans(kTests.map((t) => ({ id: t.id, n: 1000000000, unit: F.expectedUnit(t), counter: F.COUNTER_PER_PUBLIC_CALL })), kTests)],
    ['M-153 G1 n=10^9 boundary', true, () => one(plan({}))],
    ['M-153 G9 n=10^9+1', true, () => one(plan({ n: 1000000001 }))],
    ['M-153 G8 tuple unit on a tuple test', true, () => one(plan({ id: tupleId, unit: F.UNIT_PUBLIC_CALL_TUPLE }))],
    ['M-153 B1 n=10^9-1', false, () => one(plan({ n: 999999999 }))],
    ['M-153 B2 n=10^8', false, () => one(plan({ n: 100000000 }))],
    ['M-153 B3 n omitted', false, () => one(plan({ n: undefined }))],
    ['M-153 B3 n=0', false, () => one(plan({ n: 0 }))],
    ['M-153 n=10^9-0.5', false, () => one(plan({ n: 999999999.5 }))],
    ['M-153 n=Infinity', false, () => one(plan({ n: Infinity }))],
    ['M-153 n="1000000000"', false, () => one(plan({ n: '1000000000' }))],
    ['M-153 unknown id', false, () => one(plan({ id: 'randomInt/chi2/not-in-k-list' }))],
    ['M-153 B4 shuffle draws', false, () => one(plan({ id: shuffle52, n: 51000000000, unit: 'draw' }))],
    ['M-153 B5 counter per Fisher-Yates step', false, () => one(plan({ id: shuffle52, counter: 'per-fisher-yates-step' }))],
    ['M-153 B6/B7 sampled indices', false, () => one(plan({ id: sample805, n: 5000000000, unit: 'sampled-index' }))],
    ['M-153 B8 tries', false, () => one(plan({ unit: 'try' }))],
    ['M-153 B9 bytes', false, () => one(plan({ unit: 'byte' }))],
    ['M-153 B10 Lehmer digits', false, () => one(plan({ id: id(/lehmer/), unit: 'lehmer-digit' }))],
    ['M-153 B11 raw byte length', false, () => one(plan({ unit: 'raw-byte-length' }))],
    ['M-153 B12 window values on a tuple test', false, () => one(plan({ id: tupleId, unit: 'window-value' }))],
    ['M-153 B12 plain unit on a tuple test', false, () => one(plan({ id: tupleId, unit: F.UNIT_PUBLIC_CALL }))],
    ['M-153 tuple unit on a non-tuple test', false, () => one(plan({ unit: F.UNIT_PUBLIC_CALL_TUPLE }))],
    ['M-153 missing plan for one K id', false, () => F.checkRunPlans(kTests.slice(1).map((t) => ({ id: t.id, n: 1000000000, unit: F.expectedUnit(t), counter: F.COUNTER_PER_PUBLIC_CALL })), kTests)],
    ...h3Cases(m, root, { withC, tu01Text, plan, F, kTests }),
    // rule 17(i)
    ['17(i) exact counts', true, () => m.counts.checkFirstRunCounts(goodC())],
    ['17(i) STS 187 in one sequence', false, () => withC((c) => c.sts[3].NonOverlappingTemplate.pop())],
    ['17(i) STS 189 in one sequence', false, () => withC((c) => c.sts[999].NonOverlappingTemplate.push(0.5))],
    ['17(i) STS 999 sequences', false, () => withC((c) => c.sts.pop())],
    ['17(i) STS 1001 sequences', false, () => withC((c) => c.sts.push(stsSeq(STS_OK)))],
    ['17(i) STS p outside [0,1]', false, () => withC((c) => { c.sts[0].Frequency[0] = 1.5; })],
    ['17(i) STS test missing', false, () => withC((c) => { delete c.sts[0].Serial; })],
    ['17(i) BigCrush raw 159', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 159, { head: 160 }); })],
    ['17(i) BigCrush raw 161', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 161, { head: 160 }); })],
    ['17(i) BigCrush u32 159', false, () => withC((c) => { c.bigcrush.u32 = tu01Text('u32', 159, { head: 160 }); })],
    ['17(i) BigCrush u32 161', false, () => withC((c) => { c.bigcrush.u32 = tu01Text('u32', 161, { head: 160 }); })],
    ['17(i) BigCrush u32 missing', false, () => withC((c) => { delete c.bigcrush.u32; })],
    ['17(i) BigCrush SmallCrush file as BigCrush', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 160, { battery: 'SmallCrush' }); })],
    ['17(i) BigCrush -1 placeholder', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 160, { badP: 7 }); })],
    ['17(i) Dieharder counted 109', false, () => withC((c) => { c.dieharder = dhText({ counted: 109 }); })],
    ['17(i) Dieharder counted 111', false, () => withC((c) => { c.dieharder = dhText({ counted: 111 }); })],
    ['17(i) Dieharder sums missing (113 emitted)', false, () => withC((c) => { c.dieharder = dhText({ excluded: ['diehard_opso', 'diehard_oqso', 'diehard_dna'] }); })],
    ['17(i) Dieharder dna twice (115 emitted)', false, () => withC((c) => { c.dieharder = dhText({ excluded: ['diehard_opso', 'diehard_oqso', 'diehard_dna', 'diehard_dna', 'diehard_sums'] }); })],
    ['17(i) Dieharder p outside [0,1]', false, () => withC((c) => { c.dieharder = dhText({ badP: true }); })],
  ];
}

// H-3 / H-4 / H-5 (HoQ 4c7adda0/f575fe1f): a red fixture for every check whose red direction was unproven.
// Pin checks run on a scratch copy of the two frozen files; where a digest would mask the check, the
// fixture passes the tampered file's own digest so only the check under test can see the change.
function scratchRoot(root, edit) {
  const d = mkdtempSync(join(tmpdir(), 'harness-h3-'));
  for (const rel of ['verification/decision-rule-v1.md', 'verification/tool-pins-v1.1.json']) {
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    copyFileSync(join(root, rel), join(d, rel));
  }
  edit(d);
  return d;
}
function withScratch(root, edit, run) {
  const d = scratchRoot(root, edit);
  try { return run(d); } finally { rmSync(d, { recursive: true, force: true }); }
}
const RULE = 'verification/decision-rule-v1.md', TPINS = 'verification/tool-pins-v1.1.json';
function h3Cases(m, root, { withC, tu01Text, plan, F, kTests }) {
  const P = m.pins;
  const fileSha = (d, rel) => P.sha256(readFileSync(join(d, rel)));
  const editText = (d, rel, fn) => writeFileSync(join(d, rel), fn(readFileSync(join(d, rel), 'utf8')));
  const editRow = (text, i, col, v) => { const l = text.split('\n'); const c = l[i + 1].split('\t'); c[col] = v; l[i + 1] = c.join('\t'); return l.join('\n'); };
  const badTu = (edit) => withC((c) => { c.bigcrush.raw = edit(c.bigcrush.raw); });
  const arch = (bytes, pin, filename = 'x.zip') => {
    const d = mkdtempSync(join(tmpdir(), 'harness-arch-'));
    try { writeFileSync(join(d, filename), bytes); return P.checkArchiveFile(join(d, filename), filename, [pin]); } finally { rmSync(d, { recursive: true, force: true }); }
  };
  const B = Buffer.from('archive bytes');
  const goodPin = { tool: 'T', version: '1', filename: 'x.zip', byteSize: B.length, url: 'u', sha256: P.sha256(B) };
  return [
    // pins (H-3 Q23-Q26, Q28-Q30)
    ['H-3 Q23 frozen rule changed by one trailing newline (only its digest sees it)', false, () => withScratch(root, (d) => editText(d, RULE, (t) => t + '\n'), (d) => P.checkArchivePinsAgainstFrozen(d))],
    ['H-3 Q24 tool-pins changed by trailing whitespace (only its digest sees it)', false, () => withScratch(root, (d) => editText(d, TPINS, (t) => t + ' '), (d) => P.checkArchivePinsAgainstFrozen(d))],
    ['H-3 Q25 rule text loses a pin (digest re-pinned to the tampered text)', false, () => withScratch(root, (d) => editText(d, RULE, (t) => t.replace('`dieharder-3.31.1.tgz`, sha256 `6cff', '`dieharder-3.31.1.tgz`, sha256 `7cff')), (d) => P.checkArchivePinsAgainstFrozen(d, { ruleSha: fileSha(d, RULE) }))],
    ['H-3 Q26 tool-pins byte_size edited (digest re-pinned)', false, () => withScratch(root, (d) => editText(d, TPINS, (t) => t.replace('"byte_size": 904832', '"byte_size": 904833').replace('"byte_size":904832', '"byte_size":904833')), (d) => P.checkArchivePinsAgainstFrozen(d, { pinsSha: fileSha(d, TPINS) }))],
    ['H-3 Q26 tool-pins url edited (digest re-pinned)', false, () => withScratch(root, (d) => editText(d, TPINS, (t) => t.split('https://downloads.sourceforge.net/project/pracrand/PractRand_0.96.zip').join('https://example.invalid/PractRand_0.96.zip')), (d) => P.checkArchivePinsAgainstFrozen(d, { pinsSha: fileSha(d, TPINS) }))],
    ['H-3 scratch copy of the real files is green with the real digests', true, () => withScratch(root, () => {}, (d) => P.checkArchivePinsAgainstFrozen(d))],
    ['H-3 Q28 checkArchiveFile: matching bytes and pin are green', true, () => arch(B, goodPin)],
    ['H-3 Q28 checkArchiveFile: other bytes are red', false, () => arch(Buffer.from('archive bytez'), goodPin)],
    ['H-3 Q29 checkArchiveFile: right sha, wrong pinned size is red', false, () => arch(B, { ...goodPin, byteSize: B.length + 1 })],
    ['H-3 Q30 an upper-case sha256 pin is not a sha256 literal (rule text and tool-pins upper-cased too, digests re-pinned)', false, () => {
      const lo = P.ARCHIVE_PINS[0].sha256, up = lo.toUpperCase();
      return withScratch(root, (d) => { editText(d, RULE, (t) => t.split(lo).join(up)); editText(d, TPINS, (t) => t.split(lo).join(up)); },
        (d) => P.checkArchivePinsAgainstFrozen(d, { ruleSha: fileSha(d, RULE), pinsSha: fileSha(d, TPINS), pins: P.ARCHIVE_PINS.map((a, i) => (i === 0 ? { ...a, sha256: up } : a)) }));
    }],
    // H-5
    ['H-5 Dieharder and PractRand archive pins exist and match the frozen text', true, () => ['Dieharder', 'PractRand'].flatMap((t) => need(P.ARCHIVE_PINS.some((a) => a.tool === t), `no ${t} pin`))],
    ['H-5 a missing PractRand pin is red', false, () => P.checkArchivePinsAgainstFrozen(root, { pins: P.ARCHIVE_PINS.filter((a) => a.tool !== 'PractRand') })],
    ['H-5 Dieharder command with -g 200 is red against the frozen text', false, () => P.checkArchivePinsAgainstFrozen(root, { commands: { ...P.TOOL_COMMANDS, Dieharder: ['dieharder', '-a', '-Y', '0', '-g', '200', '-f', 'RAW_UINT32_FILE'] } })],
    ['H-5 PractRand nightly -tlmax 35 is red', false, () => P.checkArchivePinsAgainstFrozen(root, { commands: { ...P.TOOL_COMMANDS, 'PractRand nightly': [...P.TOOL_COMMANDS['PractRand RC'].slice(0, -1), '35'] } })],
    ['H-5 PractRand RC -tlmax 41 is red', false, () => P.checkArchivePinsAgainstFrozen(root, { commands: { ...P.TOOL_COMMANDS, 'PractRand RC': [...P.TOOL_COMMANDS['PractRand RC'].slice(0, -1), '41'] } })],
    ['H-5 runner argv: pinned Dieharder command with a file path is green', true, () => P.checkToolCommand('Dieharder', ['dieharder', '-a', '-Y', '0', '-g', '201', '-f', '/data/raw.u32'])],
    ['H-5 runner argv: Dieharder without -Y 0 is red', false, () => P.checkToolCommand('Dieharder', ['dieharder', '-a', '-g', '201', '-f', '/data/raw.u32'])],
    ['H-5 runner argv: Dieharder file replaced by an option is red', false, () => P.checkToolCommand('Dieharder', ['dieharder', '-a', '-Y', '0', '-g', '201', '-f', '-k'])],
    ['H-5 runner argv: PractRand nightly at -tlmax 40 is red', false, () => P.checkToolCommand('PractRand nightly', [...P.TOOL_COMMANDS['PractRand RC']])],
    ['H-5 runner argv: STS ./assess 100000 is red', false, () => P.checkToolCommand('NIST STS', ['./assess', '100000'])],
    // counts (H-3 Q01, Q08, Q09, Q13, Q18) and the tu01 parser (H-4)
    ['H-3 Q01 STS p = 1.0000001 is red', false, () => withC((c) => { c.sts[0].Frequency[0] = 1.0000001; })],
    ['H-3 Q01 BigCrush p = 1.0000001 is red', false, () => badTu((t) => editRow(t, 3, 4, '1.0000001'))],
    ['H-3 p = 1 and p = 0 are in range (STS)', true, () => withC((c) => { c.sts[0].Frequency[0] = 1; c.sts[1].Frequency[0] = 0; })],
    ['H-3 Q08 BigCrush rows with indices 0..159 but row 5 says 6 (names in order)', false, () => badTu((t) => editRow(t, 5, 2, '6'))],
    ['H-3 Q08 BigCrush row stream label u32 inside the raw file', false, () => badTu((t) => editRow(t, 9, 1, 'u32'))],
    ['H-3 Q09 BigCrush header ntests 159 with 160 rows', false, () => withC((c) => { c.bigcrush.raw = tu01Text('raw', 160, { head: 159 }); })],
    ['H-3 Q13 BigCrush row with 6 columns', false, () => badTu((t) => editRow(t, 2, 4, '0.5\textra'))],
    ['H-3 Q13 BigCrush row with 4 columns', false, () => badTu((t) => { const l = t.split('\n'); l[3] = l[3].split('\t').slice(0, 4).join('\t'); return l.join('\n'); })],
    ['H-4 BigCrush empty p field', false, () => badTu((t) => editRow(t, 4, 4, ''))],
    ['H-4 BigCrush blank p field', false, () => badTu((t) => editRow(t, 4, 4, ' '))],
    ['H-4 BigCrush p 0x1', false, () => badTu((t) => editRow(t, 4, 4, '0x1'))],
    ['H-4 BigCrush p +0.5', false, () => badTu((t) => editRow(t, 4, 4, '+0.5'))],
    ['H-4 BigCrush empty index field', false, () => badTu((t) => editRow(t, 0, 2, ''))],
    ['H-4 BigCrush index 0x5', false, () => badTu((t) => editRow(t, 5, 2, '0x5'))],
    ['H-4 BigCrush p in %.17g exponent form is accepted', true, () => (m.counts.parseTu01(editRow(tu01Text('raw', 3), 1, 4, '1.0000000000000001e-05')).error ? ['rejected'] : [])],
    ['H-3 Q18 one K id planned twice (all 157 present)', false, () => F.checkRunPlans([...kTests, kTests[0]].map((t) => ({ id: t.id, n: 1000000000, unit: F.expectedUnit(t), counter: F.COUNTER_PER_PUBLIC_CALL })), kTests)],
  ];
}

// Rule 8 df-table fixtures. The 9 ids fixed by HoQ's ruling are listed here on their own, so the expected
// open set is computed independently of DF_TABLE.
const RULED_IDS = Object.freeze([
  'shuffle/adjacency/n-52-i-0', 'shuffle/adjacency/n-52-i-1', 'shuffle/adjacency/n-52-i-25', 'shuffle/adjacency/n-52-i-50',
  'randomInt/chi2/min-0-max-2147483649', 'randomInt/chi2/min-0-max-4294967296', 'randomInt/chi2/min-0-max-4294967297',
  'randomInt/chi2/min-0-max-281474976710656', 'shuffle/chi2/lehmer-52',
]);
const SUPPORTS = Object.freeze([
  ['randomInt/chi2/min-0-max-2147483649', 2147483649n],
  ['randomInt/chi2/min-0-max-4294967296', 4294967296n],
  ['randomInt/chi2/min-0-max-4294967297', 4294967297n],
  ['randomInt/chi2/min-0-max-281474976710656', 281474976710656n],
]);
const F52 = (() => { let f = 1n; for (let i = 2n; i <= 52n; i++) f *= i; return f; })();
const need = (cond, msg) => (cond ? [] : [msg]);

function dfFixtureCases(D, kTests) {
  const cases = [];
  cases.push(['df: table integrity green on the real K list', true, () => D.checkDfTable(kTests)]);
  cases.push(['df: readiness open set = df-null minus the ruled ids (computed from k-tests)', true, () => {
    const want = kTests.filter((t) => t.df === null && !RULED_IDS.includes(t.id)).map((t) => t.id);
    const r = D.dfReadiness(kTests);
    return [...need(JSON.stringify(r.open) === JSON.stringify(want), 'open set differs'), ...need(r.ready === (want.length === 0), 'ready flag wrong'),
      ...need(r.dfNull === kTests.filter((t) => t.df === null).length, 'df-null count wrong')];
  }]);
  // D16 / D17 (HoQ b15a2ff5): no hidden cap on the df-null count; the k-tests digest check is exercised.
  cases.push(['df D16: a K list with 81 df-null entries (5 synthetic extra) has all 72 non-ruled open', true, () => {
    const extra = Array.from({ length: 5 }, (_, i) => ({ id: `synthetic/df-null/${i}`, primitive: 'randomInt', df: null }));
    const ks = [...kTests, ...extra];
    const want = ks.filter((t) => t.df === null && !RULED_IDS.includes(t.id)).map((t) => t.id);
    const r = D.dfReadiness(ks);
    return [...need(r.dfNull === ks.filter((t) => t.df === null).length && r.dfNull > 76, `dfNull ${r.dfNull}`),
      ...need(JSON.stringify(r.open) === JSON.stringify(want), `open ${r.open.length} != ${want.length}`), ...need(r.fixed === RULED_IDS.length, `fixed ${r.fixed}`)];
  }]);
  cases.push(['df D17: a wrong k-tests sha256 is red', false, () => D.checkDfTable(kTests, { kTestsSha256: 'f'.repeat(64) })]);
  cases.push(['df: readiness with every df-null entry fixed would be READY', true, () => {
    const ks = kTests.map((t) => (t.df === null && !RULED_IDS.includes(t.id) ? { ...t, df: 1 } : t));
    return need(D.dfReadiness(ks).ready === true, 'not ready');
  }]);
  cases.push(['df: a dropped table entry is red (extra K id with df null and no table entry stays open)', true, () => {
    const r = D.dfReadiness(kTests);
    return need(!r.open.some((id) => RULED_IDS.includes(id)), 'a ruled id is open');
  }]);
  cases.push(['df: a table with an extra (fake) df for an open entry fails the digest', false, () => D.checkDfTable(kTests, { table: { ...D.DF_TABLE, [kTests.find((t) => t.df === null && !RULED_IDS.includes(t.id)).id]: 1 } })]);
  cases.push(['df: table id not df-null in K is red', false, () => D.checkDfTable(kTests.map((t) => (t.id === RULED_IDS[0] ? { ...t, df: 5 } : t)))]);
  cases.push(['df: table id missing from K is red', false, () => D.checkDfTable(kTests.filter((t) => t.id !== RULED_IDS[4]))]);
  cases.push(['df: adjacency df = 2651, cells 52×51, expected 10^9/2652', true, () => RULED_IDS.slice(0, 4).flatMap((id) => [
    ...need(D.DF_TABLE[id] === 2651, `${id} df ${D.DF_TABLE[id]}`),
    ...need(kTests.find((t) => t.id === id).cells === 2652, `${id} cells`),
    ...need(D.ADJACENCY_CELLS === 2652 && 1000000000 / 2652 > 377073 && 1000000000 / 2652 < 377074, 'expected count'),
  ])]);
  cases.push(['df: binned df = 999 with exactly 1000 bins', true, () => RULED_IDS.slice(4).flatMap((id) => need(D.DF_TABLE[id] === 999 && D.BINS === 1000, `${id} df ${D.DF_TABLE[id]} bins ${D.BINS}`))]);
  for (const [id, r] of [...SUPPORTS, ['shuffle/chi2/lehmer-52', F52]]) {
    cases.push([`df bins ${id}: edges, cover, exact probabilities, expected ≥ 5`, true, () => {
      const f = [];
      const e = (k) => (BigInt(k) * r) / 1000n;
      f.push(...need(D.binOf(0n, r) === 0, 'v=0 not bin 0'));
      f.push(...need(D.binOf(r - 1n, r) === 999, 'v=r-1 not bin 999'));
      for (const k of [1, 499, 500, 999]) {
        f.push(...need(D.binOf(e(k), r) === k, `edge(${k}) not bin ${k}`));
        f.push(...need(D.binOf(e(k) - 1n, r) === k - 1, `edge(${k})-1 not bin ${k - 1}`));
      }
      let total = 0n;
      const widths = new Set();
      for (let k = 0; k < 1000; k++) {
        const [w, den] = D.binProbability(k, r);
        f.push(...need(den === r && w === e(k + 1) - e(k), `bin ${k} probability not width/r`));
        f.push(...need(1000000000n * w >= 5n * r, `bin ${k} expected < 5`));
        total += w; widths.add(w);
      }
      f.push(...need(total === r, 'widths do not sum to r'));
      if (r % 1000n !== 0n) {
        f.push(...need(widths.size > 1, 'non-divisible r has equal bins'));
        const [w0, d0] = D.binProbability(0, r);
        f.push(...need(w0 * 1000n !== d0, 'bin 0 probability is exactly 1/1000 for a non-divisible r'));
      } else {
        f.push(...need(widths.size === 1 && [...widths][0] === r / 1000n, 'divisible r not equal bins'));
      }
      f.push(...need(D.minExpectedOk(r) === true, 'minExpectedOk false'));
      return f;
    }]);
  }
  cases.push(['df: minExpectedOk red when a bin expects < 5 (r=1000, n=4000)', false, () => need(D.minExpectedOk(1000n, 4000n), 'below 5')]);
  cases.push(['df: minExpectedOk red with empty bins (r=999)', false, () => need(D.minExpectedOk(999n), 'empty bins')]);
  cases.push(['df: binOf refuses a Number', false, () => { try { D.binOf(5, 2147483649n); return []; } catch { return ['refused']; } }]);
  cases.push(['df: 52! divisible by 1000 and equals LEHMER_52_SUPPORT', true, () => need(F52 % 1000n === 0n && D.LEHMER_52_SUPPORT === F52, '52!')]);
  cases.push(['df: Lehmer rank in BigInt (identity 0 / bin 0, reversed 52!-1 / bin 999, swaps)', true, () => {
    const id52 = Array.from({ length: 52 }, (_, i) => i);
    const rev = [...id52].reverse();
    const swapLast = [...id52]; [swapLast[50], swapLast[51]] = [swapLast[51], swapLast[50]];
    const swapFirst = [...id52]; [swapFirst[0], swapFirst[1]] = [swapFirst[1], swapFirst[0]];
    let f51 = 1n; for (let i = 2n; i <= 51n; i++) f51 *= i;
    const r0 = D.lehmerRank(id52), r1 = D.lehmerRank(rev);
    return [
      ...need(typeof r0 === 'bigint' && r0 === 0n && D.binOf(r0, F52) === 0, 'identity'),
      ...need(typeof r1 === 'bigint' && r1 === F52 - 1n && D.binOf(r1, F52) === 999, 'reversed'),
      ...need(D.lehmerRank(swapLast) === 1n, 'swap last'),
      ...need(D.lehmerRank(swapFirst) === f51, 'swap first'),
    ];
  }]);
  return cases;
}

export function runFixtures(m, root = ROOT) {
  const out = [];
  for (const [name, expectGreen, fn] of fixtureCases(m, root)) {
    // A fixture that throws is a broken fixture, never a red result (fail closed on the self-test itself).
    let green;
    let error = null;
    try { green = fn().length === 0; } catch (e) { error = String(e && e.message); }
    out.push({ name, expectGreen, green, error, ok: error === null && green === expectGreen });
  }
  return out;
}

// Mutants. kind 'code': patch a harness module in a temp copy and run the fixtures with it.
// kind 'tree': patch a pinned file in a temp copy of the tree and run the real-tree pin checks.
// Every [from, to] must match exactly once, or the mutant is PATCH-FAILED (not proven).
export const MUTANTS = [
  ['MU-01 answer-file pin sha changed', 'code', 'pins.mjs', [["'f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666383'", "'f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666384'"]]],
  ['MU-02 driver pin sha changed', 'code', 'pins.mjs', [["'5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c88'", "'5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c89'"]]],
  ['MU-03 STS archive pin sha changed', 'code', 'pins.mjs', [["sha256: '0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157'", "sha256: '0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9158'"]]],
  ['MU-04 TestU01 archive pin sha changed', 'code', 'pins.mjs', [["sha256: 'bc1d1dd2aea7ed3b3d28eaad2c8ee55913f11ce67aec8fe4f643c1c0d2ed1cac'", "sha256: 'bc1d1dd2aea7ed3b3d28eaad2c8ee55913f11ce67aec8fe4f643c1c0d2ed1cad'"]]],
  ['MU-05 driver source byte changed', 'tree', 'verification/harness/tu01-driver.c', [['#define BUF_BYTES (1u << 20)', '#define BUF_BYTES (1u << 19)']]],
  ['MU-06 answer file 1000 -> 999 bitstreams', 'tree', 'verification/harness/sts-answers.txt', [['\n1000\n', '\n999\n']]],
  ['MU-07 floor 10^9 -> 10^9-1', 'code', 'n-floor.mjs', [['export const N_MIN = 1000000000;', 'export const N_MIN = 999999999;']]],
  ['MU-08 floor 10^9 -> 10^8', 'code', 'n-floor.mjs', [['export const N_MIN = 1000000000;', 'export const N_MIN = 100000000;']]],
  ['MU-09 floor comparison off by one', 'code', 'n-floor.mjs', [['n < N_MIN)', 'n < N_MIN - 1)']]],
  ['MU-10 unit check removed', 'code', 'n-floor.mjs', [['if (plan.unit !== expectedUnit(k)) {', 'if (false) {']]],
  ['MU-11 counter check removed', 'code', 'n-floor.mjs', [['if (plan.counter !== COUNTER_PER_PUBLIC_CALL) {', 'if (false) {']]],
  ['MU-12 STS 188 -> 187 (split 148 -> 147)', 'code', 'counts.mjs', [['export const STS_PER_SEQUENCE = 188;', 'export const STS_PER_SEQUENCE = 187;'], ['NonOverlappingTemplate: 148,', 'NonOverlappingTemplate: 147,']]],
  ['MU-13 STS 188 -> 189 (split 148 -> 149)', 'code', 'counts.mjs', [['export const STS_PER_SEQUENCE = 188;', 'export const STS_PER_SEQUENCE = 189;'], ['NonOverlappingTemplate: 148,', 'NonOverlappingTemplate: 149,']]],
  ['MU-14 STS m 1000 -> 999', 'code', 'counts.mjs', [['export const STS_SEQUENCES = 1000;', 'export const STS_SEQUENCES = 999;']]],
  ['MU-15 BigCrush 160 -> 159', 'code', 'counts.mjs', [['export const BIGCRUSH_PER_STREAM = 160;', 'export const BIGCRUSH_PER_STREAM = 159;']]],
  ['MU-16 BigCrush 160 -> 161', 'code', 'counts.mjs', [['export const BIGCRUSH_PER_STREAM = 160;', 'export const BIGCRUSH_PER_STREAM = 161;']]],
  ['MU-17 BigCrush one stream only', 'code', 'counts.mjs', [["Object.freeze(['raw', 'u32'])", "Object.freeze(['raw'])"]]],
  ['MU-18 Dieharder counted 110 -> 109', 'code', 'counts.mjs', [['export const DIEHARDER_COUNTED = 110;', 'export const DIEHARDER_COUNTED = 109;']]],
  ['MU-19 Dieharder counted 110 -> 111', 'code', 'counts.mjs', [['export const DIEHARDER_COUNTED = 110;', 'export const DIEHARDER_COUNTED = 111;']]],
  ['MU-20 Dieharder emitted 114 -> 113', 'code', 'counts.mjs', [['export const DIEHARDER_EMITTED = 114;', 'export const DIEHARDER_EMITTED = 113;']]],
  ['MU-21 Dieharder emitted 114 -> 115', 'code', 'counts.mjs', [['export const DIEHARDER_EMITTED = 114;', 'export const DIEHARDER_EMITTED = 115;']]],
  ['MU-22 Dieharder exclusion of sums dropped', 'code', 'counts.mjs', [["'diehard_dna', 'diehard_sums'])", "'diehard_dna'])"]]],
  ['MU-24 adjacency df 2651 -> 2650', 'code', 'df-table.mjs', [['export const ADJACENCY_DF = ADJACENCY_CELLS - 1;', 'export const ADJACENCY_DF = ADJACENCY_CELLS - 2;']]],
  ['MU-25 adjacency df 2651 -> 2652', 'code', 'df-table.mjs', [['export const ADJACENCY_DF = ADJACENCY_CELLS - 1;', 'export const ADJACENCY_DF = ADJACENCY_CELLS;']]],
  ['MU-26 adjacency df 2650 with digest re-pinned', 'code', 'df-table.mjs', [["  'shuffle/adjacency/n-52-i-25': ADJACENCY_DF,", "  'shuffle/adjacency/n-52-i-25': 2650,"], ["'1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63'", 'sha256(dfTableCanonical())']]],
  ['MU-27 binned df 999 -> 998', 'code', 'df-table.mjs', [['export const BINNED_DF = BINS - 1;', 'export const BINNED_DF = BINS - 2;']]],
  ['MU-28 1001 bins', 'code', 'df-table.mjs', [['export const BINS = 1000;', 'export const BINS = 1001;']]],
  ['MU-29 equal 1/1000 expectation', 'code', 'df-table.mjs', [['  return [binWidth(k, r), r];', '  return [1n, 1000n];']]],
  ['MU-30 equal-width bins r/1000', 'code', 'df-table.mjs', [['  return (BigInt(k) * r) / BigInt(BINS);', '  return BigInt(k) * (r / BigInt(BINS));']]],
  ['MU-31 non-BigInt Lehmer rank', 'code', 'df-table.mjs', [['  return rank;\n}', '  return Number(rank);\n}']]],
  ['MU-32 dropped table entry (digest re-pinned)', 'code', 'df-table.mjs', [["  'shuffle/chi2/lehmer-52': BINNED_DF,\n});", '});'], ["'1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63'", 'sha256(dfTableCanonical())']]],
  ['MU-33 readiness always READY', 'code', 'df-table.mjs', [['  return { ready: open.length === 0,', '  return { ready: true,']]],
  ['MU-34 expected >= 5 bound weakened', 'code', 'df-table.mjs', [['if (n * binWidth(k, r) < 5n * r) return false;', 'if (n * binWidth(k, r) < 4n * r) return false;']]],
  ['MU-35 df digest compare off', 'code', 'df-table.mjs', [['if (sha256(canon) !== DF_TABLE_SHA256)', 'if (false)']]],
  ['MU-36 fake df for an open entry (digest re-pinned)', 'code', 'df-table.mjs', [["  'shuffle/chi2/lehmer-52': BINNED_DF,\n});", "  'shuffle/chi2/lehmer-52': BINNED_DF,\n  'randomInt/runs/min-0-max-2': 1,\n});"], ["'1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63'", 'sha256(dfTableCanonical())']]],
  ['MU-37 collector counts Fisher-Yates steps (B4/B5)', 'code', 'collector.mjs', [['      records.push(v);\n      count += 1;', "      records.push(v);\n      count = kTest.primitive === 'shuffle' ? source.draws : count + 1;"]]],
  ['MU-38 collector counts sampled indices (B6/B7)', 'code', 'collector.mjs', [['      records.push(v);\n      count += 1;', '      if (Array.isArray(v) && kTest.primitive === \'sample\') { records.push(...v); count += v.length; } else { records.push(v); count += 1; }']]],
  ['MU-39 collector counts tries (B8)', 'code', 'collector.mjs', [['      records.push(v);\n      count += 1;', "      records.push(v);\n      count = kTest.primitive === 'randomInt' ? source.tries : count + 1;"]]],
  ['MU-40 collector counts bytes (B9/B11)', 'code', 'collector.mjs', [['      records.push(v);\n      count += 1;', "      records.push(v);\n      count = kTest.primitive === 'weightedPick' ? source.bytes : count + 1;"]]],
  ['MU-41 collector counts Lehmer digits (B10)', 'code', 'collector.mjs', [['      records.push(v);\n      count += 1;', "      records.push(v);\n      count = /Lehmer/.test(kTest.n_unit) ? source.digits : count + 1;"]]],
  ['MU-42 collector counts window values (B12)', 'code', 'collector.mjs', [['      records.push(t);\n      count += 1;', '      records.push(t);\n      count += w;']]],
  ['MU-43 witness compare off', 'code', 'collector.mjs', [['if (!Number.isSafeInteger(witnessReturns) || witnessReturns !== n * w)', 'if (false)']]],
  ['MU-44 records-length compare off', 'code', 'collector.mjs', [['if (n !== result.records.length)', 'if (false)']]],
  ['MU-45 outcome shape check off', 'code', 'collector.mjs', [['  if (bad) f.push(', '  if (false) f.push(']]],
  ['MU-46 collection floor off', 'code', 'collector.mjs', [['if (floor && !(n >= N_MIN))', 'if (false)']]],
  ['MU-47 window width always 1', 'code', 'collector.mjs', [["  if (!/tuple/.test(String(kTest.n_unit))) return 1;", '  return 1;']]],
  ['MU-48 Dieharder row-identity check off', 'code', 'counts.mjs', [['if (!got || !want || got.name !== want[0] || (want[1] !== null && got.ntup !== want[1])) {', 'if (!got || !want) {']]],
  ['MU-49 Dieharder ntup not compared', 'code', 'counts.mjs', [['|| (want[1] !== null && got.ntup !== want[1])', '']]],
  ['MU-50 BigCrush name check off', 'code', 'counts.mjs', [['if (row.name !== BIGCRUSH_TEST_NAMES[i])', 'if (false)']]],
  ['MU-51 BigCrush u32 = raw p-values check off', 'code', 'counts.mjs', [["JSON.stringify(pr.rows.map((x) => x.p)) === JSON.stringify(pu.rows.map((x) => x.p))", 'false']]],
  ['MU-52 BigCrush input sha distinct check off', 'code', 'counts.mjs', [['} else if (inputs.raw === inputs.u32) {', '} else if (false) {']]],
  ['MU-53 BigCrush input shas not required', 'code', 'counts.mjs', [["if (!inputs || typeof inputs !== 'object' || !HEX64.test(String(inputs.raw)) || !HEX64.test(String(inputs.u32))) {", 'if (false) {']]],
  ['MU-54 STS duplicate-sequence check off', 'code', 'counts.mjs', [['if (seen.has(key)) f.push(', 'if (false) f.push(']]],
  ['MU-55 BigCrush names list edited', 'code', 'counts.mjs', [['"SerialOver, r = 22"', '"SerialOver, r = 21"']]],
  ['MU-56 Dieharder rows list edited', 'code', 'counts.mjs', [['["dab_monobit2", null]', '["dab_monobit2", 12]']]],
  ['MU-57 EG-3 missing guard not reported', 'code', 'evidence-entry.mjs', [["  if (!g) return 'starts an evidence run without the entry guard';", '']]],
  ['MU-58 EG-3 guard order not checked', 'code', 'evidence-entry.mjs', [["  if (g.index > first) return 'calls the entry guard only after starting the run';", '']]],
  ['MU-59 EG-3 collector import not a run start', 'code', 'evidence-entry.mjs', [['const uses = [START.exec(s), IMPORT_COLLECTOR.exec(s)]', 'const uses = [START.exec(s)]']]],
  ['MU-60 startEvidenceRun skips the guard', 'code', 'evidence-entry.mjs', [['  assertEvidenceRunReady(root);\n  return fn();', '  return fn();']]],
  // H-3 / H-4 / H-5 (HoQ 4c7adda0/f575fe1f), HoQ's survivor numbering in the label.
  ['MU-61 (Q01) isP upper bound 1.0000001', 'code', 'counts.mjs', [['x >= 0 && x <= 1;', 'x >= 0 && x <= 1.0000001;']]],
  ['MU-62 (Q08) BigCrush row-order check off', 'code', 'counts.mjs', [["if (row.battery !== 'BigCrush' || row.stream !== s || row.index !== i) f.push", 'if (false) f.push']]],
  ['MU-63 (Q09) header ntests check off', 'code', 'counts.mjs', [['if (Number(r.head.ntests) !== BIGCRUSH_PER_STREAM) f.push', 'if (false) f.push']]],
  ['MU-64 (Q13) tu01 row width !== 5 -> < 5', 'code', 'counts.mjs', [['if (c.length !== 5) return', 'if (c.length < 5) return']]],
  ['MU-65 (Q18) duplicate-plan check off', 'code', 'n-floor.mjs', [['if (p && seen.has(p.id)) findings.push(', 'if (false) findings.push(']]],
  ['MU-66 (Q23) frozen-rule sha check off', 'code', 'pins.mjs', [["if (sha256(ruleBytes) !== ruleSha) findings.push('frozen rule sha256 changed');", '']]],
  ['MU-67 (Q24) tool-pins sha check off', 'code', 'pins.mjs', [["if (sha256(pinsBytes) !== pinsSha) findings.push('tool-pins-v1.1.json sha256 changed');", '']]],
  ['MU-68 (Q25) rule-text cross-check off', 'code', 'pins.mjs', [["if (!rule.includes('`' + a.filename + '`, sha256 `' + a.sha256 + '`')) {", 'if (false) {']]],
  ['MU-69 (Q26) tool-pins field compare off', 'code', 'pins.mjs', [['if (t.sha256 !== a.sha256 || t.url !== a.url || t.byte_size !== a.byteSize || t.version !== a.version) {', 'if (false) {']]],
  ['MU-70 (Q28) checkArchiveFile always green', 'code', 'pins.mjs', [['  if (!a) return [`no pin for archive ${filename}`];', '  return [];']]],
  ['MU-71 (Q29) archive size check off', 'code', 'pins.mjs', [['if (b.length !== a.byteSize) findings.push(', 'if (false) findings.push(']]],
  ['MU-72 (Q30) HEX64 accepts upper case', 'code', 'pins.mjs', [['const HEX64 = /^[0-9a-f]{64}$/;', 'const HEX64 = /^[0-9a-fA-F]{64}$/;']]],
  ['MU-73 (H-4) tu01 p parsed with Number()', 'code', 'counts.mjs', [['    if (!TU01_P.test(c[4])) return', '    if (false) return']]],
  ['MU-74 (H-4) tu01 index parsed with Number()', 'code', 'counts.mjs', [['    if (!TU01_INDEX.test(c[2])) return', '    if (false) return']]],
  ['MU-75 (H-5) PractRand pin dropped', 'code', 'pins.mjs', [["    tool: 'PractRand', version: '0.96'", "    tool: 'PractRandX', version: '0.96'"]]],
  ['MU-76 (H-5) command cross-check off', 'code', 'pins.mjs', [["if (!c || !rule.includes('`' + c.join(' ') + '`')) findings.push", 'if (false) findings.push']]],
  ['MU-77 (H-5) nightly command check off', 'code', 'pins.mjs', [["  if (!nightlyOk) findings.push(", '  if (false) findings.push(']]],
  ['MU-78 (H-5) runner argv placeholder accepts an option', 'code', 'pins.mjs', [["a === '' || a.startsWith('-')", "a === ''"]]],
  ['MU-79 (H-5) runner argv value compare off', 'code', 'pins.mjs', [['    else if (a !== w) f.push(', '    else if (false) f.push(']]],
  ['MU-80 (D16) hidden df-null cap of 76', 'code', 'df-table.mjs', [['const nullIds = kTests.filter((t) => t.df === null).map((t) => t.id);', 'const nullIds = kTests.filter((t) => t.df === null).map((t) => t.id).slice(0, 76);']]],
  ['MU-81 (D17) k-tests sha256 check off', 'code', 'df-table.mjs', [['if (kTestsSha256 !== undefined && kTestsSha256 !== K_TESTS_SHA256) f.push(', 'if (false) f.push(']]],
  ['MU-23 p-value range check removed', 'code', 'counts.mjs', [['return typeof x === \'number\' && Number.isFinite(x) && x >= 0 && x <= 1;', 'return true;']]],
];

function patch(text, pairs) {
  let t = text;
  for (const [from, to] of pairs) {
    const n = t.split(from).length - 1;
    if (n !== 1) return null;
    t = t.replace(from, () => to);
  }
  return t;
}

function copyTree(root, dst) {
  for (const rel of ['verification/decision-rule-v1.md', 'verification/tool-pins-v1.1.json', K_TESTS]) {
    mkdirSync(dirname(join(dst, rel)), { recursive: true });
    copyFileSync(join(root, rel), join(dst, rel));
  }
  mkdirSync(join(dst, 'verification/harness'), { recursive: true });
  for (const f of readdirSync(HERE)) copyFileSync(join(HERE, f), join(dst, 'verification/harness', f));
}

export async function runMutants(root = ROOT, mutants = MUTANTS) {
  const results = [];
  for (const [name, kind, file, pairs] of mutants) {
    const tmp = mkdtempSync(join(tmpdir(), 'harness-mutant-'));
    try {
      copyTree(root, tmp);
      const target = kind === 'code' ? join(tmp, 'verification/harness', file) : join(tmp, file);
      const patched = patch(readFileSync(target, 'utf8'), pairs);
      if (patched === null) { results.push({ name, status: 'PATCH-FAILED' }); continue; }
      writeFileSync(target, patched);
      let fixtures;
      if (kind === 'code') fixtures = runFixtures(await load(join(tmp, 'verification/harness')), tmp);
      else fixtures = runFixtures(await load(HERE), tmp);
      const killers = fixtures.filter((f) => !f.ok).map((f) => f.name);
      results.push({ name, status: killers.length ? 'KILLED' : 'SURVIVED', killers });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  return results;
}

export async function selfTest(root = ROOT) {
  const fails = [];
  const fx = runFixtures(await load(HERE), root);
  for (const f of fx) if (!f.ok) fails.push(`fixture ${f.name}: expected ${f.expectGreen ? 'green' : 'red'}, got ${f.error !== null ? 'ERROR ' + f.error : f.green ? 'green' : 'red'}`);
  const mu = await runMutants(root);
  for (const r of mu) if (r.status !== 'KILLED') fails.push(`mutant ${r.name}: ${r.status}`);
  return { fixtures: fx, mutants: mu, fails };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--self-test')) {
    const r = await selfTest();
    if (r.fails.length) { console.error(`harness self-test FAILED:\n${r.fails.join('\n')}`); process.exit(1); }
    console.log(`harness self-test: ${r.fixtures.length} fixtures as expected, ${r.mutants.filter((x) => x.status === 'KILLED').length}/${r.mutants.length} mutants killed`);
  } else {
    const f = await runChecks();
    if (f.length) { f.forEach((x) => console.log(x)); console.log(`harness preconditions: ${f.length} finding(s)`); process.exit(1); }
    console.log('harness preconditions: pins, M-153 floor and rule 8 df table integrity green (readiness: see evidence-entry.mjs)');
  }
}
