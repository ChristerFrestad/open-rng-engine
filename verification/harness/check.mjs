// Evidence-harness precondition checks and their self-test (mutants). Decision rule v1 (FROZEN 5d09c75a).
//   default:     rule 15 pins (answer file, driver, archives vs the frozen text) and the M-153 floor on the
//                157-entry K list (rule 8 / rule 15 TODO-CTO-1). Exit 1 on any finding.
//   --self-test: synthetic fixtures for rule 8 (M-153), rule 15 / 17(ii) pins and rule 17(i) counts, then
//                every mutant in MUTANTS; exit 1 unless all fixtures behave, every mutant is killed and no
//                patch failed. No evidence data is read or produced.
// Rule 8 df table (72 entries): NOT built here; see verification/harness/README.md (open ambiguity).
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
  return { pins: await imp('pins.mjs'), floor: await imp('n-floor.mjs'), counts: await imp('counts.mjs') };
}

export async function runChecks(root = ROOT, mods) {
  const m = mods || (await load(HERE));
  const kTests = loadKTests(root);
  const findings = [...m.pins.checkHarnessPins(root), ...m.pins.checkArchivePinsAgainstFrozen(root)];
  if (kTests.length !== 157) findings.push(`K list has ${kTests.length} entries, expected 157 (rule 8 K′)`);
  const plans = kTests.map((t) => ({ id: t.id, n: m.floor.N_MIN, unit: m.floor.expectedUnit(t), counter: m.floor.COUNTER_PER_PUBLIC_CALL }));
  findings.push(...m.floor.checkRunPlans(plans, kTests));
  return findings;
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
  return [
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
    console.log('harness preconditions: pins and M-153 floor green (rule 8 df table not built)');
  }
}
