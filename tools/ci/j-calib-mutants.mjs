// G-58 (HoQ report 505599e..96aaf91, CTO batch J): calibration-harness and labkit-adapter mutants.
// Each mutant is applied to a scratch copy of this tree; then EVERY digest that binds those files is re-pinned
// in the copy (results-j statistic / harness / adapter digests, the adapter pin in the test), so a mutant can
// only die to a behavioural test, never to a digest pin. test/labkit-calibration.test.mjs runs on the copy;
// the failing test names are the killers. Baseline (no mutant, re-pin only) must be green.
// Usage: node tools/ci/j-calib-mutants.mjs   (exit 0 iff baseline green and every mutant killed by a non-digest test)
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const ST = 'verification/statistic/wave1-statistic.mjs', SRC = 'verification/calibration/wave1-source.mjs';
const AD = 'verification/labkit/aes-ctr-ref.mjs', CAL = 'verification/calibration/wave1-calibrate.mjs';
const TEST = 'test/labkit-calibration.test.mjs', RJ = 'verification/calibration/wave1-results-j.json';
const DIGEST_TESTS = [/^labkit adapter: pinned digest/, /^J calibration results: statistic and harness digests/];
const SCREEN_TEST = 'test/dt-screen.test.mjs';
const MC_TEST = 'test/dt-mc.test.mjs', MCF = 'verification/mc/dt-mc.mjs';

const MUTANTS = [
  ['HM-29 KS D one-sided (D+ only)', [[ST, 'D = Math.max(D, (i + 1) / n - s[i], s[i] - i / n);', 'D = Math.max(D, (i + 1) / n - s[i]);']]],
  ['HM-30 KS p without the Stephens factor', [[ST, 'const lam = (en + 0.12 + 0.11 / en) * D;', 'const lam = en * D;']]],
  ['HM-31 flag interval lower bound 2 -> 0', [[ST, 'FLAGS: Object.freeze([2, 22])', 'FLAGS: Object.freeze([0, 22])']]],
  ['HM-32 pass-rule outcome floor 10^6 -> 0', [[ST, 'minOutcomes >= A6.N', 'minOutcomes >= 0']]],
  ['HM-33 outcomes per replication miscounted (one per observation)', [[ST, 'h[Math.min(k, nRaw - 1)] += 1; outcomes += t;', 'h[Math.min(k, nRaw - 1)] += 1; outcomes += 1;']]],
  ['HM-34 N_CAL 10^6 -> 10^5 (M_cal shrinks)', [[SRC, 'export const N_CAL = 1e6,', 'export const N_CAL = 1e5,']]],
  ['HM-35 below() rejection limit +1', [[AD, 'const lim = TWO32 - (TWO32 % r);', 'const lim = TWO32 - (TWO32 % r) + 1;']]],
  ['HM-37 RefStream restarts the keystream at every 1 MiB refill', [
    [AD, "    this.cipher = createCipheriv('aes-256-ctr', Buffer.from(keyHex, 'hex'), ivFor(stream, rep));", "    this.mk = () => createCipheriv('aes-256-ctr', Buffer.from(keyHex, 'hex'), ivFor(stream, rep)); this.cipher = this.mk();"],
    [AD, '    const b = this.cipher.update(this.zero);', '    this.cipher = this.mk(); const b = this.cipher.update(this.zero);']]],
  ['HM-39 lumping threshold 5 -> 4', [[ST, 'const five = 5n * law.den;', 'const five = 4n * law.den;']]],
  ['HM-40 duplicates urns not reset per block', [[ST, 'const urns = new Set(); let C = 0, t = 0;', 'const urns = (globalThis.__hm40 ??= new Set()); let C = 0, t = 0;']]],
  // K1 R-DT-SCREEN (CPO-R116a / HoQ R-DT-SCREEN), run against test/dt-screen.test.mjs.
  ['SC-1 k dropped', [[ST, 'const logBound = Math.LN2 + Math.log(k) - M * klMax;', 'const logBound = Math.LN2 - M * klMax;']], SCREEN_TEST],
  ['SC-2 sum of b_i instead of k*min', [[ST, 'const logBound = Math.LN2 + Math.log(k) - M * klMax;', 'const logBound = Math.log(Array.from(o, (x, j) => 2 * Math.exp(-M * klSafe(x / M, lumped.cells[j]))).reduce((a, b) => a + b, 0));']], SCREEN_TEST],
  ['SC-3 factor 2 dropped', [[ST, 'const logBound = Math.LN2 + Math.log(k) - M * klMax;', 'const logBound = Math.log(k) - M * klMax;']], SCREEN_TEST],
  ['SC-4 KL arguments swapped', [[ST, 'const kl = klSafe(o[j] / M, lumped.cells[j]);', 'const kl = klSafe(Math.min(Math.max(lumped.cells[j], 1e-300), 1), Math.min(Math.max(o[j] / M, 1e-300), 1 - 1e-16));']], SCREEN_TEST],
  ['SC-5 one tail only (excess)', [[ST, 'const kl = klSafe(o[j] / M, lumped.cells[j]);', 'const kl = o[j] / M > lumped.cells[j] ? klSafe(o[j] / M, lumped.cells[j]) : 0;']], SCREEN_TEST],
  ['SC-6 < replaced by <=', [[ST, 'export const screenFails = (logBound) => logBound < SCREEN.LOG_THRESHOLD;', 'export const screenFails = (logBound) => logBound <= SCREEN.LOG_THRESHOLD;']], SCREEN_TEST],
  ['SC-7 threshold drift 1e-10 -> 1e-9', [[ST, 'LOG_THRESHOLD: Math.log(1e-10)', 'LOG_THRESHOLD: Math.log(1e-9)']], SCREEN_TEST],
  ['SC-8 rounding direction flipped', [[ST, 'klBernoulli(q, p) * (1 - SCREEN.SAFETY_REL) - SCREEN.SAFETY_ABS', 'klBernoulli(q, p) * (1 + SCREEN.SAFETY_REL) + SCREEN.SAFETY_ABS']], SCREEN_TEST],
  // K2 R-DT-MC framework and duplicates exact sampler, run against test/dt-mc.test.mjs.
  ['MC-1 p_MC off by one (#>= / (B+1))', [[MCF, 'export const pMC = (ge) => (1 + ge) / MC.B_PLUS_1;', 'export const pMC = (ge) => ge / MC.B_PLUS_1;']], MC_TEST],
  ['MC-2 assembled p over B instead of B+1', [[MCF, 'p_mc: (1 + ge) / (man.B + 1)', 'p_mc: (1 + ge) / man.B']], MC_TEST],
  ['MC-3 ties not counted (> instead of >=)', [[MCF, 'export const exceeds = (x2sim, x2obs) => x2sim >= x2obs;', 'export const exceeds = (x2sim, x2obs) => x2sim > x2obs;']], MC_TEST],
  ['MC-4 flag boundary 62 -> < 62', [[MCF, 'export const mcFlag = (ge) => ge <= MC.FLAG_MAX_GE;', 'export const mcFlag = (ge) => ge < MC.FLAG_MAX_GE;']], MC_TEST],
  ['MC-5 stream reuse across blocks', [[MCF, 'return new RefStream(MC.DOMAIN, ((entry << 11) | block) >>> 0, keyHex);', 'return new RefStream(MC.DOMAIN, ((entry << 11) | 0) >>> 0, keyHex);']], MC_TEST],
  ['MC-6 B drift (1,004,798)', [[MCF, 'B: 1004799,', 'B: 1004798,']], MC_TEST],
  ['MC-7 sampler exact tie path skipped', [[MCF, 'if (l > 0 && hi[l - 1] === a && lo[l - 1] === b) {', 'if (false) {']], MC_TEST],
  // K3b G-67 / G-71 (HoQ A9 / A10), run against test/dt-mc.test.mjs.
  ['MC-8 observed X² computed differently (not S.pearson)', [[MCF, 'return { x2: S.pearson(h, lumped, man.M).x2, observed_sha256', 'return { x2: c.reduce((a, x, j) => a + (x - man.M * lumped.cells[j]) ** 2 / (man.M * lumped.cells[j] + 1), 0), observed_sha256']], MC_TEST],
  ['MC-9 scalar observed X² accepted', [[MCF, "export function observedX2(man, lumped, observed) {\n", "export function observedX2(man, lumped, observed) {\n  if (typeof observed === 'number') return { x2: observed, observed_sha256: sha(String(observed)) };\n"]], MC_TEST],
  ['MC-10 M = sum of counts not checked', [[MCF, "  if (M !== man.M) throw new Error(", "  if (false) throw new Error("]], MC_TEST],
  ['MC-11 M > 10^9 not refused', [[MCF, "  if (man.M > M_MAX) throw new Error(", "  if (false) throw new Error("]], MC_TEST],
  ['MC-12 manifest constants not checked', [[MCF, "  checkManifestConstants(man);\n", ""]], MC_TEST],
  ['MC-13 block #>= not re-verified', [[MCF, "  if (geOf(x.x2, obs.x2) !== x.ge) throw new Error(", "  if (false) throw new Error("]], MC_TEST],
  ['MC-14 block from another observed vector accepted', [[MCF, "  if (x.observed_sha256 !== obs.observed_sha256 || x.x2obs !== obs.x2) throw new Error(", "  if (false) throw new Error("]], MC_TEST],
  // K3c G-69 (report G-68 survivors).
  ['HS-3 screen k = raw length', [[ST, 'const logBound = Math.LN2 + Math.log(k) - M * klMax;', 'const logBound = Math.LN2 + Math.log(h.length) - M * klMax;']], SCREEN_TEST],
  ['HS-5 screen counts not lumped', [[ST, "o[lumped.map[i]] += h[i];\n  let worst", "o[i < k ? i : 0] += h[i];\n  let worst"]], SCREEN_TEST],
  ['HM-MC5 tie-path rejection returns the last cell', [[MCF, "        if (j === k) continue; // X >= den·2^s: reject", "        if (j === k) return k - 1;"]], MC_TEST],
  ['HM-MC6 tie-path remainder not aligned', [[MCF, "rest >>= extra; // keep exactly L - 64 bits", "// keep exactly L - 64 bits"]], MC_TEST],
  // K3d G-69 (HoQ A9; report G-68): G-56 identity over all 26 entries, run against test/g69-evidence-identity.test.mjs.
  ['GM-3 evidence path reverses shuffle records', [['verification/harness/wave1-evidence.mjs', 'return records[i++]; };', 'const r = records[i++]; return Array.isArray(r) ? [...r].reverse() : r; };']], 'test/g69-evidence-identity.test.mjs'],
  ['GM-5 evidence path skips one record per 4096 (duplicates)', [['verification/harness/wave1-evidence.mjs', 'return records[i++]; };', "if (e.kind === 'dup' && i % 4096 === 4095) i++; return records[i++]; };"]], 'test/g69-evidence-identity.test.mjs'],
  // G-64 (HoQ A11) parent-side authority, run against test/g64-proc-mem.test.mjs.
  ['JL-1 launcher spawns without its own readiness check', [['verification/harness/evidence-launcher.mjs', '  assertEvidenceRunReady(ROOT);\n  const ks', '  const ks']], 'test/g64-proc-mem.test.mjs'],
  ['GM-6 evidenceStatistic trusts the in-process stamp (A11 probe B)', [['verification/harness/wave1-evidence.mjs', '  if (!launcherCounted(result)) throw', "  if (!launcherCounted(result) && globalThis[Symbol.for('open-rng-engine/entropy-' + 'backstop/v1')]?.evidence?.stamped?.(result) == null) throw"]], 'test/g64-proc-mem.test.mjs'],
  // K3a G-64 static ban on defining the backstop marker, run against test/g64-marker-ban.test.mjs.
  ['MB-1 marker ban never matches a definition', [['tools/ci/marker-ban.mjs', "if (s.includes(MARK_TEXT) && DEFINE.test(s)) out.push(", "if (false) out.push("]], 'test/g64-marker-ban.test.mjs'],
  ['MB-2 marker ban skips verification/', [['tools/ci/marker-ban.mjs', "if (rel !== 'test') walk(p);", "if (rel !== 'test' && rel !== 'verification') walk(p);"]], 'test/g64-marker-ban.test.mjs'],
];

const sha = (d, rel) => createHash('sha256').update(readFileSync(join(d, rel))).digest('hex');
function scratch(edits) {
  const d = mkdtempSync(join(tmpdir(), 'jcm-'));
  for (const x of ['package.json', 'src', 'test', 'tools', 'verification', 'packages']) cpSync(join(ROOT, x), join(d, x), { recursive: true });
  symlinkSync(join(ROOT, 'node_modules'), join(d, 'node_modules'));
  const oldAd = sha(d, AD);
  for (const [rel, from, to] of edits) {
    const s = readFileSync(join(d, rel), 'utf8');
    if (s.split(from).length !== 2) throw new Error(`anchor not unique in ${rel}: ${from}`);
    writeFileSync(join(d, rel), s.replace(from, to));
  }
  // Re-pin every digest that binds the mutated files (the mutant must die to behaviour, not to a pin).
  const doc = JSON.parse(readFileSync(join(d, RJ), 'utf8'));
  const edited = new Set(edits.map(([rel]) => rel)); // re-pin only what the mutant edits (baseline: nothing)
  if (edited.has(ST)) doc.statistic.sha256 = sha(d, ST);
  if (edited.has(SRC)) doc.harness_sha256['wave1-source.mjs'] = sha(d, SRC);
  if (edited.has(CAL)) doc.harness_sha256['wave1-calibrate.mjs'] = sha(d, CAL);
  if (edited.has(AD)) doc.adapter.file_sha256 = sha(d, AD);
  writeFileSync(join(d, RJ), JSON.stringify(doc));
  const H2 = 'verification/calibration/wave1-results.json'; const h2 = JSON.parse(readFileSync(join(d, H2), 'utf8'));
  if (h2.adapter && h2.adapter.file_sha256) { h2.adapter.file_sha256 = sha(d, AD); writeFileSync(join(d, H2), JSON.stringify(h2)); }
  const t = readFileSync(join(d, TEST), 'utf8'); writeFileSync(join(d, TEST), t.split(oldAd).join(sha(d, AD)));
  return d;
}
function run(label, edits, testFile = TEST) {
  return new Promise((done) => {
    const d = scratch(edits);
    const env = { ...process.env }; delete env.NODE_OPTIONS;
    const c = spawn(process.execPath, ['--test', '--test-reporter=tap', testFile], { cwd: d, env });
    let out = ''; c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { out += b; });
    c.on('close', (status) => {
      rmSync(d, { recursive: true, force: true });
      const failed = [...out.matchAll(/^not ok \d+ - (.*)$/gm)].map((m) => m[1].trim());
      done({ label, status, failed, behavioural: failed.filter((f) => !DIGEST_TESTS.some((r) => r.test(f))) });
    });
  });
}

const base = await run('baseline (re-pin only)', []);
console.log(`${base.label}: ${base.status === 0 && base.failed.length === 0 ? 'green' : `NOT green: ${base.failed.join('; ')}`}`);
let bad = base.status !== 0 || base.failed.length !== 0;
const P = 4; const res = []; let next = 0;
await Promise.all(Array.from({ length: P }, async () => { while (next < MUTANTS.length) { const i = next++; res[i] = await run(...MUTANTS[i]); } }));
for (const r of res) {
  const ok = r.behavioural.length > 0;
  if (!ok) bad = true;
  console.log(`${r.label}: ${ok ? 'killed' : 'SURVIVED'} by ${r.behavioural.length ? r.behavioural.join(' | ') : '(nothing but digests)'}`);
}
console.log(`j-calib-mutants: ${res.filter((r) => r.behavioural.length).length}/${res.length} killed by behavioural tests`);
process.exit(bad ? 1 : 0);
