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
  doc.statistic.sha256 = sha(d, ST); doc.harness_sha256['wave1-source.mjs'] = sha(d, SRC);
  doc.harness_sha256['wave1-calibrate.mjs'] = sha(d, CAL); doc.adapter.file_sha256 = sha(d, AD);
  writeFileSync(join(d, RJ), JSON.stringify(doc));
  const H2 = 'verification/calibration/wave1-results.json'; const h2 = JSON.parse(readFileSync(join(d, H2), 'utf8'));
  if (h2.adapter && h2.adapter.file_sha256) { h2.adapter.file_sha256 = sha(d, AD); writeFileSync(join(d, H2), JSON.stringify(h2)); }
  const t = readFileSync(join(d, TEST), 'utf8'); writeFileSync(join(d, TEST), t.split(oldAd).join(sha(d, AD)));
  return d;
}
function run(label, edits) {
  return new Promise((done) => {
    const d = scratch(edits);
    const env = { ...process.env }; delete env.NODE_OPTIONS;
    const c = spawn(process.execPath, ['--test', '--test-reporter=tap', TEST], { cwd: d, env });
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
