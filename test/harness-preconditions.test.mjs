// Evidence-harness preconditions, decision rule v1 (FROZEN 5d09c75a): rule 15 pins (STS answer file,
// TestU01 driver, archives), rule 8 / M-153 floor, rule 17(i) counts, and the mutant self-test.
// Digest literals are held here on their own (not imported from the harness), so a changed pin in
// verification/harness/pins.mjs and a changed pinned file are each red here.
// Rule 8 df table (HoQ ruling: all df-null K entries): the 9 ruled entries are fixed; the rest stay open and
// the harness is NOT-READY, which check:ph0 reports without failing and the evidence-run entry refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import * as pins from '../verification/harness/pins.mjs';
import * as floor from '../verification/harness/n-floor.mjs';
import * as counts from '../verification/harness/counts.mjs';
import { runChecks, selfTest, runMutants, loadKTests } from '../verification/harness/check.mjs';
import * as df from '../verification/harness/df-table.mjs';
import { harnessReadiness, assertEvidenceRunReady, scriptFileFindings, scriptFileFinding, startEvidenceRun } from '../verification/harness/evidence-entry.mjs';
import * as col from '../verification/harness/collector.mjs';

const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const ANSWERS_SHA = 'f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666383';
const DRIVER_SHA = '5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c88';
const STS_ZIP_SHA = '0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157';
const TU01_ZIP_SHA = 'bc1d1dd2aea7ed3b3d28eaad2c8ee55913f11ce67aec8fe4f643c1c0d2ed1cac';

test('rule 15: STS answer file bytes are the pinned literal', () => {
  assert.equal(sha('verification/harness/sts-answers.txt'), ANSWERS_SHA);
  assert.equal(readFileSync('verification/harness/sts-answers.txt', 'utf8'), '0\nraw-stream.bin\n1\n0\n1000\n1\n');
  assert.equal(pins.HARNESS_FILE_PINS['verification/harness/sts-answers.txt'], ANSWERS_SHA);
});

test('rule 15: TestU01 driver source is the pinned literal', () => {
  assert.equal(sha('verification/harness/tu01-driver.c'), DRIVER_SHA);
  assert.equal(pins.HARNESS_FILE_PINS['verification/harness/tu01-driver.c'], DRIVER_SHA);
  assert.match(readFileSync('verification/harness/tu01-driver.c', 'utf8'), /unif01_CreateExternGenBits/);
});

test('rule 15 / 17(ii): archive pins equal the frozen rule text', () => {
  const rule = readFileSync('verification/decision-rule-v1.md', 'utf8');
  assert.ok(rule.includes('`sts-2_1_2.zip`, sha256 `' + STS_ZIP_SHA + '`'));
  assert.ok(rule.includes('`TestU01-1.2.3.zip`, sha256 `' + TU01_ZIP_SHA + '`'));
  assert.deepEqual(pins.ARCHIVE_PINS.map((a) => a.sha256), [STS_ZIP_SHA, TU01_ZIP_SHA, '6cff0ff8394c553549ac7433359ccfc955fb26794260314620dfa5e4cd4b727f', 'e4caf7fda98b2c597bbda3b576753cf5a0f6047aab837c82be370ab798a672e1']);
  assert.deepEqual(pins.checkArchivePinsAgainstFrozen('.'), []);
});

test('rule 17(ii): an archive whose bytes differ from the pin is red', () => {
  const f = pins.checkArchiveFile('verification/harness/tu01-driver.c', 'TestU01-1.2.3.zip');
  assert.ok(f.some((x) => /rule 17\(ii\)/.test(x)));
  assert.ok(pins.checkArchiveFile('/nonexistent/sts-2_1_2.zip', 'sts-2_1_2.zip').length > 0);
});

test('preconditions: real tree green (pins + M-153 floor on all 157 K ids)', async () => {
  assert.deepEqual(await runChecks(), []);
});

test('rule 8 / M-153: floor is 10^9 and the boundary is exact', () => {
  assert.equal(floor.N_MIN, 1e9);
  const k = loadKTests();
  const p = (n) => floor.checkPlan({ id: 'randomInt/chi2/min-0-max-38', n, unit: 'public-call', counter: floor.COUNTER_PER_PUBLIC_CALL }, k);
  assert.equal(p(1e9).ok, true);
  assert.equal(p(1e9 + 1).ok, true);
  assert.equal(p(1e9 - 1).ok, false);
  assert.match(p(1e9 - 1).reason, /n < 10\^9 public-call outcomes/);
  assert.equal(p(1e8).ok, false);
  assert.equal(p(0).ok, false);
  assert.equal(p(undefined).ok, false);
});

test('rule 17(i): expected counts are the frozen numbers', () => {
  assert.equal(counts.STS_PER_SEQUENCE, 188);
  assert.equal(Object.values(counts.STS_PER_TEST).reduce((a, b) => a + b, 0), 188);
  assert.equal(counts.BIGCRUSH_PER_STREAM, 160);
  assert.deepEqual([...counts.BIGCRUSH_STREAMS], ['raw', 'u32']);
  assert.equal(counts.DIEHARDER_EMITTED, 114);
  assert.equal(counts.DIEHARDER_COUNTED, 110);
  assert.deepEqual([...counts.DIEHARDER_EXCLUDED], ['diehard_opso', 'diehard_oqso', 'diehard_dna', 'diehard_sums']);
});

test('self-test: every fixture as expected, all 81 mutants killed, none PATCH-FAILED', async () => {
  const r = await selfTest();
  assert.deepEqual(r.fails, []);
  assert.equal(r.mutants.length, 92);
  assert.ok(r.mutants.every((m) => m.status === 'KILLED'));
});

test('self-test: a mutant whose patch does not apply is PATCH-FAILED, not killed', async () => {
  const [r] = await runMutants(undefined, [['MU-X bad patch', 'code', 'counts.mjs', [['no such text in counts.mjs', 'x']]]]);
  assert.equal(r.status, 'PATCH-FAILED');
});

test('check:ph0 wiring: b8 step runs the harness checks on this tree', () => {
  const out = execFileSync('node', ['tools/ci/b8-dependencies.mjs'], { encoding: 'utf8' });
  assert.match(out, /harness preconditions: 0 finding\(s\)/);
  // HoQ b15a2ff5: the numbers are computed from k-tests and the ruled list, not hard-coded.
  const { dfNull, fixed, open } = expectedDfCounts();
  assert.ok(out.includes(`harness readiness: NOT-READY (rule 8 df fixed ${fixed} of ${dfNull} df-null entries, ${open} open;`), out);
  assert.match(readFileSync('package.json', 'utf8'), /node tools\/ci\/b8-dependencies\.mjs && node tools\/ci\/b8-dependencies\.mjs --self-test/);
});

test('no evidence data in the harness directory', () => {
  const files = execFileSync('git', ['ls-files', '--others', '--cached', '--exclude-standard', 'verification/harness'], { encoding: 'utf8' }).split('\n').filter(Boolean).sort();
  assert.deepEqual(files, ['verification/harness/README.md', 'verification/harness/check.mjs', 'verification/harness/collector.mjs', 'verification/harness/counts.mjs', 'verification/harness/df-table.mjs', 'verification/harness/evidence-entry.mjs', 'verification/harness/n-floor.mjs', 'verification/harness/pins.mjs', 'verification/harness/sts-answers.txt', 'verification/harness/tool-binaries.json', 'verification/harness/tu01-driver.c']);
});

// The 9 ids HoQ ruled (b15a2ff5), held here on their own so the counts are computed independently of DF_TABLE.
const RULED = ['shuffle/adjacency/n-52-i-0', 'shuffle/adjacency/n-52-i-1', 'shuffle/adjacency/n-52-i-25', 'shuffle/adjacency/n-52-i-50',
  'randomInt/chi2/min-0-max-2147483649', 'randomInt/chi2/min-0-max-4294967296', 'randomInt/chi2/min-0-max-4294967297',
  'randomInt/chi2/min-0-max-281474976710656', 'shuffle/chi2/lehmer-52'];
function expectedDfCounts() {
  const nulls = loadKTests().filter((t) => t.df === null).map((t) => t.id);
  const fixed = nulls.filter((id) => RULED.includes(id)).length;
  return { dfNull: nulls.length, fixed, open: nulls.length - fixed };
}

// Digest and df literals held here on their own (not imported from the table).
const DF_DIGEST = '1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63';
test('rule 8 df table: ruled values, digest literal, K-list sha', () => {
  const kSha = sha('verification/k-tests-v1.1.json');
  assert.equal(kSha, 'f75299de7fa063b96e2a031ec7072ed4fe34f219a4bc04e3534125b973097c4c');
  assert.equal(df.DF_TABLE_SHA256, DF_DIGEST);
  assert.equal(createHash('sha256').update(df.dfTableCanonical()).digest('hex'), DF_DIGEST);
  for (const i of [0, 1, 25, 50]) assert.equal(df.DF_TABLE[`shuffle/adjacency/n-52-i-${i}`], 2651);
  for (const id of ['randomInt/chi2/min-0-max-2147483649', 'randomInt/chi2/min-0-max-4294967296', 'randomInt/chi2/min-0-max-4294967297', 'randomInt/chi2/min-0-max-281474976710656', 'shuffle/chi2/lehmer-52']) assert.equal(df.DF_TABLE[id], 999);
  assert.deepEqual(Object.keys(df.DF_TABLE).sort(), [...RULED].sort());
  assert.deepEqual(df.checkDfTable(loadKTests(), { kTestsSha256: kSha }), []);
});

test('rule 8 readiness: open set computed from k-tests; evidence-run entry refuses; PH0 does not fail', () => {
  const k = loadKTests();
  const nulls = k.filter((t) => t.df === null);
  const c = expectedDfCounts();
  assert.equal(c.fixed, RULED.length);
  const r = harnessReadiness();
  assert.equal(r.ready, false);
  assert.equal(r.df.dfNull, c.dfNull);
  assert.equal(r.df.dfNull, nulls.length);
  assert.equal(r.df.open.length, c.open);
  assert.deepEqual(r.df.open, nulls.map((t) => t.id).filter((id) => !RULED.includes(id)));
  assert.ok(r.df.open.every((id) => !(id in df.DF_TABLE)));
  assert.throws(() => assertEvidenceRunReady(), (e) => e.message.includes(`harness NOT-READY: rule 8 df open for ${c.open} of ${c.dfNull} df-null entries`));
});

test('rule 8 bins: exact BigInt probabilities, unequal for non-divisible r, Lehmer rank in BigInt', () => {
  const r = 2147483649n;
  assert.deepEqual(df.binProbability(0, r), [2147483n, r]);
  assert.notEqual(df.binProbability(0, r)[0] * 1000n, r);
  assert.equal(df.binOf(0n, r), 0);
  assert.equal(df.binOf(r - 1n, r), 999);
  assert.throws(() => df.binOf(1, r), TypeError);
  assert.equal(df.minExpectedOk(r), true);
  const id52 = Array.from({ length: 52 }, (_, i) => i);
  assert.equal(df.lehmerRank(id52), 0n);
  assert.equal(df.lehmerRank([...id52].reverse()), df.factorial(52) - 1n);
  assert.equal(df.binOf(df.lehmerRank([...id52].reverse()), df.LEHMER_52_SUPPORT), 999);
});

// EG-1 / EG-2 / EG-3 (HoQ addendum 1 4195afbc; HoQ b15a2ff5 report). Digests held here on their own.
test('EG-2: pinned BigCrush names and Dieharder rows (digest literals, counts, exclusions)', () => {
  const h = (x) => createHash('sha256').update(JSON.stringify(x)).digest('hex');
  assert.equal(h(counts.BIGCRUSH_TEST_NAMES), '02ddf54c9695d249c28eb2fa90ed04f0ace64494ebaf32ca7ea8cc22c60f448b');
  assert.equal(h(counts.DIEHARDER_ROWS), '9c5f7a5d80dad768d213dff1034950353a90dfa6a4b8e263f9991a15786a61b3');
  assert.equal(counts.BIGCRUSH_TEST_NAMES.length, 160);
  assert.equal(counts.DIEHARDER_ROWS.length, 114);
  assert.equal(counts.DIEHARDER_ROWS.filter((r) => !counts.DIEHARDER_EXCLUDED.includes(r[0])).length, 110);
  for (const x of counts.DIEHARDER_EXCLUDED) assert.equal(counts.DIEHARDER_ROWS.filter((r) => r[0] === x).length, 1);
});

test('EG-1: collector result is accepted only when n = records = witness returns / w', () => {
  const k = loadKTests().find((t) => t.id === 'randomInt/chi2/min-0-max-38');
  let x = 0;
  const w = col.witness(() => (x = (x + 7) % 38));
  const r = col.collect(k, w.call, 50);
  assert.deepEqual(col.checkCollected(r, k, w.count(), { floor: false, grant: false }), []);
  assert.notDeepEqual(col.checkCollected({ ...r, n: 100 }, k, w.count(), { floor: false, grant: false }), []);
  assert.notDeepEqual(col.checkCollected(r, k, w.count() * 2, { floor: false, grant: false }), []);
  assert.notDeepEqual(col.checkCollected(r, k, w.count()), []);
});

test('EG-3 / G-45: no interpreter scripts in the tree; startEvidenceRun refuses while NOT-READY and opens no grant', async () => {
  assert.deepEqual(scriptFileFindings(), []);
  assert.match(String(scriptFileFinding('verification/harness/run.py', '')), /G-45/);
  assert.equal(scriptFileFinding('tools/ci/x.mjs', '#!/usr/bin/env node\n'), null);
  let ran = false;
  await assert.rejects(startEvidenceRun(async () => { ran = true; }), /harness NOT-READY/);
  assert.equal(ran, false);
});

// H-5 (HoQ 4c7adda0/f575fe1f): Dieharder and PractRand archive pins and the rule 15 commands, as literals
// held here on their own.
test('H-5 rule 15: Dieharder and PractRand archive pins and pinned commands', () => {
  const by = Object.fromEntries(pins.ARCHIVE_PINS.map((a) => [a.filename, [a.byteSize, a.sha256]]));
  assert.deepEqual(by['dieharder-3.31.1.tgz'], [1149780, '6cff0ff8394c553549ac7433359ccfc955fb26794260314620dfa5e4cd4b727f']);
  assert.deepEqual(by['PractRand_0.96.zip'], [904832, 'e4caf7fda98b2c597bbda3b576753cf5a0f6047aab837c82be370ab798a672e1']);
  assert.equal(pins.TOOL_COMMANDS.Dieharder.join(' '), 'dieharder -a -Y 0 -g 201 -f RAW_UINT32_FILE');
  assert.equal(pins.TOOL_COMMANDS['PractRand RC'].join(' '), 'RNG_test stdin32 -tf 1 -te 0 -tlmin 10 -tlmax 40');
  assert.equal(pins.TOOL_COMMANDS['PractRand nightly'].join(' '), 'RNG_test stdin32 -tf 1 -te 0 -tlmin 10 -tlmax 34');
  assert.equal(pins.TOOL_COMMANDS['NIST STS'].join(' '), './assess 1000000');
  assert.deepEqual(pins.checkArchivePinsAgainstFrozen(process.cwd()), []);
});

test('H-4 tu01 parser: empty, blank, hex and signed fields are malformed', () => {
  const c = counts;
  const head = '# tu01-driver v1\tbattery=BigCrush\tstream=raw\tntests=1\twords=0\n';
  for (const [idx, p] of [['0', ''], ['0', ' '], ['0', '0x1'], ['', '0.5'], ['0x0', '0.5'], ['0', '+0.5'], ['0', '-0'], [' 0', '0.5'], ['0', 'Infinity']]) {
    assert.match(String(c.parseTu01(`${head}BigCrush\traw\t${idx}\tname\t${p}\n`).error), /malformed/, `${idx}/${p}`);
  }
  for (const p of ['0', '1', '0.5', '1.0000000000000001e-05', '2.2250738585072014e-308']) {
    assert.equal(c.parseTu01(`${head}BigCrush\traw\t0\tname\t${p}\n`).error, undefined, p);
  }
});
