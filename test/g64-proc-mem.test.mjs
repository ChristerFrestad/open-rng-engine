// G-64 (HoQ A11): the /proc/self/mem forgery, reproduced, and the launcher design that makes it count for
// nothing. The READY-world launcher cases (LW-proc-mem-steal and the G64-M* mutants) are in tools/ci/g39-mutants.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runCounted, launcherCounted, contentDigest } from '../verification/harness/evidence-launcher.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const STEAL = readFileSync(join(ROOT, 'test/fixtures/g64-proc-mem-steal.txt'), 'utf8');
const env = () => { const e = { ...process.env }; delete e.NODE_OPTIONS; return e; };

test('A11 reproduced: a secret held anywhere in the guarded process is recovered from /proc/self/mem (K3a scheme forgeable)', () => {
  const d = mkdtempSync(join(tmpdir(), 'g64-mem-'));
  try {
    const f = join(d, 'holder.mjs');
    // The K3a shape: a 32-byte key consumed from stdin into a closure at startup, then untrusted code runs.
    writeFileSync(f, `import { readFileSync } from 'node:fs';\nconst held = (() => { const s = Buffer.from(readFileSync(0)); return () => s.length; })();\n${STEAL}\n`);
    // A fixed high-entropy key (npm test runs under the backstop, which bans entropy calls in tests); the scan
    // does not use the key's value, only the child's memory.
    const secret = createHash('sha256').update('g64-a11-key-1').digest(); // 32 distinct bytes, passes the scan's filter
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, f], { env: env(), input: secret, stdio: ['pipe', 'pipe', 'pipe', 'pipe'], maxBuffer: 1 << 28, timeout: 120_000 });
    assert.equal(r.status, 0, String(r.stderr));
    const p = { id: 'x', n: 5, digest: 'cd'.repeat(32), grant: 'grant-1@1' };
    const want = createHmac('sha256', secret).update(`${p.id}\n${p.n}\n${p.digest}\n${p.grant}`).digest('hex');
    const lines = String(r.output[3] ?? '').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(lines.length > 0, 'the scan wrote candidate lines');
    assert.ok(lines.some((o) => o.mac === want), 'a forged line verifies under the child-held key: any child-held secret is no authority');
    assert.ok(!String(r.stdout).includes(secret.toString('hex')), 'the key is never printed');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('G-64: the launcher holds no secret, sends nothing on stdin, and checks readiness itself before spawning', () => {
  const src = readFileSync(join(ROOT, 'verification/harness/evidence-launcher.mjs'), 'utf8');
  assert.doesNotMatch(src, /randomBytes|createHmac|input:/);
  const bs = readFileSync(BACKSTOP, 'utf8');
  assert.doesNotMatch(bs, /createHmac|channelSecret|readFileSync\(0\)/);
  const d = mkdtempSync(join(tmpdir(), 'g64-nr-'));
  try {
    const mark = join(d, 'ran');
    const f = join(d, 'runner.mjs'); writeFileSync(f, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(mark)}, '1');\n`);
    assert.throws(() => runCounted(f, [], { cwd: d }), /harness NOT-READY/);
    assert.equal(existsSync(mark), false, 'nothing was spawned while NOT-READY');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('G-64 (HoQ A11 probe B): a complete in-process forged marker in a plain process gets nothing past evidenceStatistic', () => {
  const d = mkdtempSync(join(tmpdir(), 'g64-b-'));
  try {
    const f = join(d, 'forger.mjs');
    const ev = pathToFileURL(join(ROOT, 'verification/harness/wave1-evidence.mjs')).href;
    const col = pathToFileURL(join(ROOT, 'verification/harness/collector.mjs')).href;
    // Under npm test the child inherits the real preload, so the plant fails (the marker is already real); run
    // standalone or by j-calib-mutants (no preload), the plant succeeds: this is HoQ's plain-process probe B.
    writeFileSync(f, `let planted = true;\ntry {\n${readFileSync(join(ROOT, 'test/fixtures/g64-complete-forger.txt'), 'utf8')}\n} catch { planted = false; }
const C = await import(${JSON.stringify(col)}); const Ev = await import(${JSON.stringify(ev)});
const k = { id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } };
let res; try { res = C.collectCounted(k, () => 1, 5); } catch { res = C.collect(k, () => 1, 5); }
const out = { planted, inProcessAccepted: C.grantStampError(res) === null };
try { Ev.evidenceStatistic('randomInt/coupon-collector/min-0-max-2', { ...res, id: 'randomInt/coupon-collector/min-0-max-2' }, 1); out.statistic = 'ACCEPTED'; } catch (e) { out.statistic = e.message; }
try { Ev.evidenceStatistic('randomInt/coupon-collector/min-0-max-2', res, 1); out.statistic2 = 'ACCEPTED'; } catch (e) { out.statistic2 = e.message; }
console.log('FORGER ' + JSON.stringify(out));
`);
    const r = spawnSync(process.execPath, [f], { env: env(), encoding: 'utf8', timeout: 60_000 });
    const m = /FORGER (.*)/.exec(r.stdout); assert.ok(m, r.stderr);
    const o = JSON.parse(m[1]);
    if (o.planted) assert.equal(o.inProcessAccepted, true, 'the planted forger does fool the in-process stamp check (not authority)');
    assert.match(o.statistic, /not counted by the evidence launcher \(G-64\)/);
    assert.match(o.statistic2, /not counted by the evidence launcher \(G-64\)/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('G-64: launcherCounted is false for anything the launcher did not count, and digests use the backstop canonical form', () => {
  const r = { id: 'x', n: 2, records: [1n, 2] };
  assert.equal(launcherCounted(r), false); assert.equal(launcherCounted(null), false); assert.equal(launcherCounted({ ...r, digest: contentDigest(r) }), false);
  assert.equal(contentDigest(r), contentDigest({ id: 'x', n: 2, records: [1n, 2] }));
  assert.notEqual(contentDigest(r), contentDigest({ id: 'x', n: 2, records: [1, 2] }));
});
