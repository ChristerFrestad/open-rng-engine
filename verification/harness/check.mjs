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
  return { pins: await imp('pins.mjs'), floor: await imp('n-floor.mjs'), counts: await imp('counts.mjs'), df: await imp('df-table.mjs') };
}

export async function runChecks(root = ROOT, mods) {
  const m = mods || (await load(HERE));
  const kTests = loadKTests(root);
  const kBytes = readFileSync(join(root, K_TESTS));
  const kSha = m.pins.sha256(kBytes);
  const findings = [...m.pins.checkHarnessPins(root), ...m.pins.checkArchivePinsAgainstFrozen(root), ...m.df.checkDfTable(kTests, { kTestsSha256: kSha })];
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
  const seqs = Array.from({ length: nseq }, () => stsSeq(counts));
  if (edit) edit(seqs);
  return seqs;
}
function tu01Text(stream, n, { battery = 'BigCrush', head = n, badP } = {}) {
  const rows = Array.from({ length: n }, (_, i) => `${battery}\t${stream}\t${i}\tsyn_${i}\t${i === badP ? -1 : (i + 0.5) / (n + 1)}`);
  return [`# tu01-driver v1\tbattery=${battery}\tstream=${stream}\tntests=${head}\twords=0`, ...rows].join('\n') + '\n';
}
function dhText({ counted = 110, excluded = ['diehard_opso', 'diehard_oqso', 'diehard_dna', 'diehard_sums'], badP = false } = {}) {
  const row = (name, p) => `${name.padStart(20)}|   0|       100|     100|${p.toFixed(8)}|  PASSED  `;
  const lines = ['#=============================================================================#', '        test_name   |ntup| tsamples |psamples|  p-value |Assessment'];
  for (const n of excluded) lines.push(row(n, 0.5));
  for (let i = 0; i < counted; i++) lines.push(row(`syn_counted_${i}`, badP && i === 0 ? 1.5 : (i + 0.5) / (counted + 1)));
  return lines.join('\n') + '\n';
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
  const goodC = () => ({ sts: stsRun(STS_OK), bigcrush: { raw: tu01Text('raw', 160), u32: tu01Text('u32', 160) }, dieharder: dhText() });
  const withC = (edit) => { const c = goodC(); edit(c); return m.counts.checkFirstRunCounts(c); };
  const D = m.df;
  const dfCases = dfFixtureCases(D, kTests);
  return [
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
