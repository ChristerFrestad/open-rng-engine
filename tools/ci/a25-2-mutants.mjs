#!/usr/bin/env node
// A25-6 (i), (ii), (iii), (v), A25-2 header/launcher and A29-3 mutants (HoQ addendum 1 L642-L647, L786; CTO split
// A25-2-SPLIT-v1 with Addendum C = interface v2). Owner: Test
// Engineer. Runs test/r-g64-a25-2.test.mjs from a BARE parent (no NODE_OPTIONS, no preload) on a temp copy of this
// tree: first unmutated (must be green, 0 skipped), then once per mutant (must fail = KILLED). Exit 0 only when the
// baseline is green and every mutant applied and was killed. A mutant whose pattern is not found is NOT-APPLIED and
// fails the run (fail-closed): an integrator who renames a frozen v1 name must update the mutant, not lose it.
// Never edits this tree. Usage: node tools/ci/a25-2-mutants.mjs [--only <id-prefix>]
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const TEST_FILE = 'test/r-g64-a25-2.test.mjs';
const BS = 'tools/ci/entropy-backstop.mjs', MAN = 'tools/ci/a25-manifest.mjs', LOCK = 'tools/ci/a25-lockdown.mjs';
const LAUNCH = 'verification/harness/stream-launcher.mjs';
// verifyLoad(url, bytes) (interface v2) closes over the manifest, so a mutant that must act on membership reads the
// same manifest itself, from the locator, when a25-manifest.mjs is evaluated by the preload. If the locator is gone by
// then, MEMBERS is null and the mutant degrades to "verifyLoad checks nothing" (still a mutant, less selective).
const MEMBERS = `(() => { try { const fs = process.getBuiltinModule('node:fs'), u = process.getBuiltinModule('node:url'), pa = process.getBuiltinModule('node:path');
  const m = JSON.parse(fs.readFileSync(process.env.ENTROPY_BACKSTOP_MANIFEST, 'utf8'));
  return (url) => { const f = u.fileURLToPath(url); const r = pa.relative(m.root, f).split(pa.sep).join('/'); return Object.hasOwn(m.entries, r); };
} catch { return null; } })()`;

// Edits: [file, old, new] replaces the one occurrence of `old`; [file, { override, params, body }] renames
// `export function <override>(` to a private name and appends an exported replacement that may call it as __orig(...),
// so a mutant of a frozen v1 function needs only its name and signature, not the integrator's code. [file, { re, to }]
// replaces the one match of a RegExp in that file, or (file '*') in exactly one tools/ci/*.mjs file.
// R-A29-3 (residual, HoQ ruling 2026-11-25 ~21:20 CET): the real randomFillSync was probed through the INSTALLED gate
// (helper mode, preload, node 24.22.1, base 150edc5d, 2-call budget): (a) a Uint8Array whose buffer was transferred
// away with structuredClone(buf, { transfer: [buf.buffer] }) reaches the native fill with byteLength 0 and the fill
// RETURNS (no throw); (b) offset/size out of range never reaches the fill: the gate refuses 3 arguments with exit 87.
// No black-box path makes the native fill throw, so the finally-clear of the installed gate is carried by factory
// identity (test/r-g64-a25.test.mjs pins that the installed gate is makeHelperGate(origFill)) plus the seam tests in
// test/r-g64-a25-2.test.mjs, killed by A29-3-M11..M15 below.
// EQ-1 (equivalent mutant, not in the list on purpose; HoQ accepted as EQUIVALENT): "a wrapped primitive aborts in
// helper mode only while the gate token is CLEAR". The token is set only for the duration of the synchronous native
// fill (token = true; try { fill(target) } finally { token = false }), and the native fill runs no JavaScript: no
// callback, no getter on the view (the gate already rejected anything but a plain Uint8Array with intrinsic
// byteLength). So no wrapped primitive can ever be called while the token is set, every A25-6(v) re-entry takes the
// token-clear path, and that mutant behaves identically on every input: no test can kill it.
const MUTANTS = [
  // A25-6 (i) -> 89
  ['A6i-M1 verifyLoad lets a module outside the manifest through', [[MAN, { override: 'verifyLoad', params: 'url, bytes', body: `const inM = ${MEMBERS}; if (inM === null || !inM(url)) return; return __orig(url, bytes);` }]]],
  ['A6i-M2 EXIT_A25_MANIFEST_OUTSIDE is not distinct (89 -> 90)', [['*', { re: /\bEXIT_A25_MANIFEST_OUTSIDE\s*=\s*89\b/, to: 'EXIT_A25_MANIFEST_OUTSIDE = 90' }]]],
  // A25-6 (ii) -> 90
  ['A6ii-M3 verifyLoad checks membership only, not the bytes of a manifest module', [[MAN, { override: 'verifyLoad', params: 'url, bytes', body: `const inM = ${MEMBERS}; if (inM === null || inM(url)) return; return __orig(url, bytes);` }]]],
  ['A6ii-M4 EXIT_A25_MANIFEST_DIGEST is not distinct (90 -> 89)', [['*', { re: /\bEXIT_A25_MANIFEST_DIGEST\s*=\s*90\b/, to: 'EXIT_A25_MANIFEST_DIGEST = 89' }]]],
  // A25-2 header binding (Addendum C) -> 90 before any module loads
  ['A2h-M16 readManifest ignores the header-bound sha256 (swapped manifest accepted)', [[MAN, { override: 'readManifest', params: 'path, expectedSha256', body: "let s = expectedSha256; try { s = process.getBuiltinModule('node:crypto').createHash('sha256').update(process.getBuiltinModule('node:fs').readFileSync(path)).digest('hex'); } catch { /* missing: let the original decide */ } return __orig(path, s);" }]]],
  // A25-2 launcher (Addendum C): the launcher overrides an inherited locator
  ['A2l-M17 helperSpawnEnv keeps an inherited ENTROPY_BACKSTOP_MANIFEST', [[LAUNCH, { override: 'helperSpawnEnv', params: 'base, opts', body: "const e = __orig(base, opts); if (base && Object.hasOwn(base, 'ENTROPY_BACKSTOP_MANIFEST')) e.ENTROPY_BACKSTOP_MANIFEST = base.ENTROPY_BACKSTOP_MANIFEST; return e;" }]]],
  ['A2l-M19 helperSpawnEnv passes inherited sha-like ENTROPY_BACKSTOP_* / MANIFEST_* values through (a sha outside the grant)', [[LAUNCH, { override: 'helperSpawnEnv', params: 'base, opts', body: "const e = __orig(base, opts); for (const [k, v] of Object.entries(base || {})) if (/^(ENTROPY_BACKSTOP_|MANIFEST_)/.test(k) && /^[0-9a-f]{64}$/.test(String(v))) e[k] = v; return e;" }]]],
  ['A2l-M18 helperSpawnEnv sets no manifest locator of its own', [[LAUNCH, { override: 'helperSpawnEnv', params: 'base, opts', body: "const e = __orig(base, opts); delete e.ENTROPY_BACKSTOP_MANIFEST; return e;" }]]],
  // A25-6 (iii) -> 91
  ['A6iii-M5 installLockdown installs nothing', [[LOCK, { override: 'installLockdown', params: '...args', body: 'return undefined;' }]]],
  ['A6iii-M6 EXIT_A25_CODEGEN is not distinct (91 -> 86)', [['*', { re: /\bEXIT_A25_CODEGEN\s*=\s*91\b/, to: 'EXIT_A25_CODEGEN = 86' }]]],
  // A25-6 (v) -> 86 on every call
  ['A6v-M7 wrapped primitives do not abort in helper mode', [[BS, '    if (HELPER_MODE) helperAbort(EXIT_A25_TOKEN,', '    if (false) helperAbort(EXIT_A25_TOKEN,']]],
  ['A6v-M8 helper-mode abort only on sampled calls (i mod 2^k = 0)', [[BS, '    if (HELPER_MODE) helperAbort(EXIT_A25_TOKEN,', '    if (HELPER_MODE && HELPER && (HELPER.counts().gate_calls < HELPER_FIRST_WALK || ((HELPER.counts().gate_calls - 1) & HELPER_MASK) === 0)) helperAbort(EXIT_A25_TOKEN,']]],
  ['A6v-M9 helper-mode abort only before the first gate call', [[BS, '    if (HELPER_MODE) helperAbort(EXIT_A25_TOKEN,', '    if (HELPER_MODE && (!HELPER || HELPER.counts().gate_calls === 0)) helperAbort(EXIT_A25_TOKEN,']]],
  ['A6v-M10 EXIT_A25_TOKEN is not distinct (86 -> 88)', [[BS, 'export const EXIT_A25_TOKEN = 86;', 'export const EXIT_A25_TOKEN = 88;']]],
  // A29-3: the gate token is cleared in finally
  ['A29-3-M11 gate token not cleared in finally', [[BS, '    try { fill(target); } finally { token = false; }', '    fill(target); token = false;']]],
  ['A29-3-M12 a throwing fill is swallowed (gate returns an unfilled target)', [[BS, '    try { fill(target); } finally { token = false; }', '    try { fill(target); } catch { /* swallowed */ } finally { token = false; }']]],
  ['A29-3-M13 the fill error is replaced, not rethrown', [[BS, '    try { fill(target); } finally { token = false; }', "    try { fill(target); } catch { throw new Error('fill failed'); } finally { token = false; }"]]],
  ['A29-3-M14 token cleared only on a thrown Error, not on other thrown values', [[BS, '    try { fill(target); } finally { token = false; }', '    try { fill(target); token = false; } catch (e) { if (e instanceof Error) token = false; throw e; }']]],
  ['A29-3-M15 token not set again after a throw (re-entry check dead after the first failure)', [[BS, '    token = true;\n    try { fill(target); } finally { token = false; }', '    if (!helperGate.failed) token = true;\n    try { fill(target); } catch (e) { helperGate.failed = true; throw e; } finally { token = false; }']]],
];

function copyTree() {
  const dst = mkdtempSync(join(tmpdir(), 'a25-2-mut-'));
  for (const d of ['src', 'tools', 'test', 'verification']) if (existsSync(join(ROOT, d))) cpSync(join(ROOT, d), join(dst, d), { recursive: true });
  for (const f of ['package.json', 'tsconfig.json']) if (existsSync(join(ROOT, f))) cpSync(join(ROOT, f), join(dst, f));
  return dst;
}
function applyEdit(root, [file, a, b]) {
  if (file === '*') {
    const dir = join(root, 'tools/ci'); const hits = readdirSync(dir).filter((f) => f.endsWith('.mjs') && f !== 'a25-2-mutants.mjs' && a.re.test(readFileSync(join(dir, f), 'utf8')));
    if (hits.length !== 1) return `pattern ${a.re} found in ${hits.length} tools/ci files`;
    file = `tools/ci/${hits[0]}`;
  }
  const p = join(root, file);
  if (!existsSync(p)) return `${file} missing`;
  const t = readFileSync(p, 'utf8');
  if (typeof a === 'string') {
    const n = t.split(a).length - 1; if (n !== 1) return `pattern found ${n} times in ${file}`;
    writeFileSync(p, t.replace(a, () => b)); return null;
  }
  if (a.re) { const n = (t.match(new RegExp(a.re.source, 'g')) || []).length; if (n !== 1) return `${a.re} found ${n} times in ${file}`; writeFileSync(p, t.replace(a.re, () => a.to)); return null; }
  const decl = `export function ${a.override}(`, async = `export async function ${a.override}(`;
  const n = t.split(decl).length - 1 + t.split(async).length - 1;
  if (n !== 1) return `${decl} found ${n} times in ${file}`;
  const isAsync = t.includes(async), priv = `__te_orig_${a.override}`;
  const renamed = t.replace(isAsync ? async : decl, () => `${isAsync ? 'async ' : ''}function ${priv}(`);
  writeFileSync(p, `${renamed}\nexport ${isAsync ? 'async ' : ''}function ${a.override}(${a.params}) { const __orig = ${priv}; ${a.body} }\n`);
  return null;
}
function runTests(root) {
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.ENTROPY_BACKSTOP_CHANNEL; delete env.ENTROPY_BACKSTOP_HELPER; delete env.ENTROPY_BACKSTOP_MANIFEST;
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', TEST_FILE], { cwd: root, env, encoding: 'utf8', timeout: 900000, maxBuffer: 64 << 20 });
  const num = (k) => { const m = new RegExp(`^# ${k} (\\d+)$`, 'm').exec(r.stdout || ''); return m ? Number(m[1]) : -1; };
  const failed = [...(r.stdout || '').matchAll(/^not ok \d+ - (.*)$/gm)].map((m) => m[1]);
  return { status: r.status, tests: num('tests'), pass: num('pass'), fail: num('fail'), skipped: num('skipped'), failed };
}

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
let bad = false;
const base = copyTree();
let b;
try { b = runTests(base); } finally { rmSync(base, { recursive: true, force: true }); }
console.log(`baseline (bare, unmutated): status=${b.status} tests=${b.tests} pass=${b.pass} fail=${b.fail} skipped=${b.skipped}`);
if (b.status !== 0 || b.fail !== 0 || b.skipped !== 0 || b.tests <= 0) { bad = true; for (const f of b.failed) console.log(`  baseline failed: ${f}`); }
let killed = 0, survived = 0, notApplied = 0;
for (const [id, edits] of MUTANTS) {
  if (only && !id.startsWith(only)) continue;
  const root = copyTree();
  try {
    const why = edits.map((e) => applyEdit(root, e)).find((x) => x !== null);
    if (why) { notApplied++; bad = true; console.log(`${id} | NOT-APPLIED (${why})`); continue; }
    const r = runTests(root);
    if (r.status !== 0 && r.fail > 0) { killed++; console.log(`${id} | ${r.fail}/${r.tests} failed | KILLED`); }
    else if (r.status !== 0) { bad = true; console.log(`${id} | status ${r.status}, no failing test (timeout or crash) | ERROR`); }
    else { survived++; bad = true; console.log(`${id} | 0/${r.tests} failed | SURVIVED`); }
  } finally { rmSync(root, { recursive: true, force: true }); }
}
console.log(`a25-2-mutants: ${killed} killed, ${survived} survived, ${notApplied} not applied; baseline ${b.status === 0 && b.fail === 0 && b.skipped === 0 ? 'green' : 'RED'}`);
process.exit(bad ? 1 : 0);
