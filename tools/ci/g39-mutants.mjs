#!/usr/bin/env node
// G-39 mutant runner (HoQ 4c7adda0/f575fe1f §3.4; CTO batch D). Each mutant turns one rule of the child
// policy off in a copy of the tree and runs the real entropy-backstop-check there. It is killed when the
// check fails AND every expected bypass are reported as reached.
// Must run WITHOUT the backstop (`node tools/ci/g39-mutants.mjs`): under it, every node child is forced to
// load this repo's backstop, so a mutated copy can never load alone. That is the policy working, and also
// why this is not part of `npm test`. It is not wired into check:ph0 because package.json is frozen.
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')]) {
  console.error('g39-mutants: run without the backstop preload (see header)');
  process.exit(2);
}
const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const HOQ8 = ['hoq-1-export-n', 'hoq-2-unset-indirect', 'hoq-3-exec-c', 'hoq-4-script-file', 'hoq-5-python', 'hoq-6-perl', 'hoq-7-env-printf', 'hoq-8-declare-x'];
export const G39_MUTANTS = [
  ['G39-M1 child allowlist off', "  const opts = options || {};\n  if (kind === 'fork') {", "  const opts = options || {};\n  if (kind !== 'fork') return { node: String(file).endsWith('node') };\n  if (kind === 'fork') {", HOQ8],
  ['G39-M2 proof check off', '  if (existsSync(path)) return true;', '  return true;', ['proof-missing-async', 'proof-missing-sync']],
  ['G39-M3 child never writes proof', '  const p = process.env[PROOF_ENV];\n  if (!p) return;', '  const p = process.env[PROOF_ENV];\n  return;', null],
  ['G39-M4 binding guard off', '    if (REFUSED_BINDINGS.includes(String(name))) {', '    if (false) {', ['binding-spawn-sync']],
  ['G39-M5 dlopen guard off', "  if (typeof process.dlopen === 'function' && !process.dlopen._backstopBinding) {", '  if (false) {', ['dlopen']],
  ['G39-M6 git repo-config allowlist off', '      for (const k of gitConfigKeys(t)) if (!GIT_CONFIG_KEYS.some((r) => r.test(k)))', '      for (const k of gitConfigKeys(t)) if (false)', ['git-repo-config']],
  ['G39-M7 shell line plain-word check off', "    if (!words.every((w) => PLAIN_WORD.test(w)) || words[0].includes('=')) refuseChild", '    if (false) refuseChild', ['shell-chain-after-allowed']],
];

// G-45 (HoQ report c9d7c93..dbd4e00, addendum 1 A7): one mutant per evasion class. HM-17/18/19/21 are HoQ's
// survivor numbers against the old text contract; here they are the same weaknesses at the spawn layer.
const G45_ALL = ['indirect-bin', 'guard-in-comment', 'dead-guard', 'swallowed-guard', 'guard-in-string', 'bracket-spawn', 'verification-dir'];
export const G45_MUTANTS = [
  ['G45-M1 evidence-tool rule off', '  if (names.length) {', '  if (false) {', [...G45_ALL, 'RW-green-dieharder']],
  ['G45-M2 argv/shell words not scanned for tool names', '  const words = [String(exe), ...(argv || []).map(String)];', '  const words = [String(exe)];', ['path-join-arg']],
  ['G45-M3 interpreter rule off', '  if (INTERPRETER.test(base)) refuseChild', '  if (false) refuseChild', ['python-plain']],
  ['G45-M4 (HM-18) exec/execSync shell lines not checked', 'function evidenceSpawnCheck(kind, exe, argv, opts) {\n', "function evidenceSpawnCheck(kind, exe, argv, opts) {\n  if (kind === 'shell' || opts.shell) return null;\n", ['exec-sync', 'exec-async']],
  ['G45-M5 (HM-17) RNG_test not an evidence tool', "'assess', 'RNG_test']);", "'assess']);", ['rng-test', 'RW-green-rngtest']],
  ['G45-M6 grant opened without running the guard', '  ev.assertEvidenceRunReady();\n  const g = Object.freeze', '  const g = Object.freeze', ['grant-not-ready']],
  ['G45-M7 launch without an open grant', "  if (!evidenceGrants.has(g) || activeGrant !== g || grantEntry === null) refuseChild('evidence tool launch without an open grant (G-45)');\n", '', ['launch-without-grant']],
  ['G45-M8 raw spawn allowed while a grant is open', '    const ok = launching !== null && ', '    const ok = activeGrant !== null || launching !== null && ', ['RW-raw-in-run', 'RW-shell-in-run']],
  ['G45-M9 grant not closed after the run', '  if (activeGrant === g) activeGrant = null;\n  evidenceGrants.delete(g);\n', '', ['RW-after-run-launch']],
  ['G45-M10 (HM-21) callers under verification/ exempt', 'function evidenceSpawnCheck(kind, exe, argv, opts) {\n', "function evidenceSpawnCheck(kind, exe, argv, opts) {\n  if (String(process.argv[1] || '').includes('/verification/')) return { node: false, evidence: true };\n", ['verification-dir']],
];

// READY world: a copy of the tree whose readiness is forced true, so the grant path can be exercised.
const RW_CASES = [
  ['RW-green-dieharder', true, (T) => `const r = launch(${T.DH}, ['-a']); if (r.error || r.status !== 0) process.exit(3);`],
  ['RW-green-rngtest', true, (T) => `const r = launch(${T.PR}, ['stdin32']); if (r.error || r.status !== 0) process.exit(3);`],
  ['RW-raw-in-run', false, (T) => `spawnSync(${T.DH}, ['-a']);`],
  ['RW-shell-in-run', false, (T) => `execSync(${T.DH} + ' -a');`],
  ['RW-launch-interpreter', false, () => `launch('/usr/bin/python3', ['-c', '1']);`],
  ['RW-after-run-launch', false, (T) => `globalThis.__L = launch;`, (T) => `globalThis.__L(${T.DH}, ['-a']);`],
  ['RW-after-run-raw', false, (T) => `const r = launch(${T.DH}, ['-a']); if (r.error || r.status !== 0) process.exit(3);`, (T) => `spawnSync(${T.DH}, ['-a']);`],
];

function readyWorld(d) {
  const reached = [];
  const ee = join(d, 'verification/harness/evidence-entry.mjs');
  const s = readFileSync(ee, 'utf8');
  const from = '  return { ready: df.ready, df };';
  if (!s.includes(from)) return ['RW-anchor-missing'];
  writeFileSync(ee, s.replace(from, '  return { ready: true, df };'));
  const bin = join(d, 'rw-bin');
  mkdirSync(bin, { recursive: true });
  const T = {};
  for (const [k, t] of [['DH', 'die' + 'harder'], ['PR', 'RNG' + '_test']]) { copyFileSync(realpathSync('/bin/true'), join(bin, t)); chmodSync(join(bin, t), 0o755); T[k] = JSON.stringify(join(bin, t)); }
  const bs = join(d, 'tools/ci/entropy-backstop.mjs');
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  for (const [label, green, body, after] of RW_CASES) {
    const f = join(d, `rw-${label}.mjs`);
    writeFileSync(f, `import { spawnSync, execSync } from 'node:child_process';\nconst { startEvidenceRun } = await import(${JSON.stringify(pathToFileURL(ee).href)});\nawait startEvidenceRun(async ({ launch }) => { ${body(T)} });\n${after ? after(T) : ''}\nconsole.log('RW-OK');\n`);
    const r = spawnSync(process.execPath, ['--import', bs, f], { cwd: d, encoding: 'utf8', timeout: 60_000, env });
    const out = `${r.stdout}\n${r.stderr}`;
    const ok = green ? r.status === 0 && /RW-OK/.test(out) : r.status !== 0 && /\(G-45\)/.test(out) && !/RW-OK/.test(out);
    if (!ok) reached.push(label);
  }
  return reached;
}

// Without the preload, startEvidenceRun must refuse before anything runs.
function noPreload() {
  const d = mkdtempSync(join(tmpdir(), 'g45-np-'));
  try {
    const f = join(d, 'np.mjs');
    writeFileSync(f, `const { startEvidenceRun } = await import(${JSON.stringify(pathToFileURL(join(ROOT, 'verification/harness/evidence-entry.mjs')).href)});\nlet ran = false;\ntry { await startEvidenceRun(async () => { ran = true; }); } catch (e) { console.error(e.message); }\nprocess.exit(ran ? 0 : 1);\n`);
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, [f], { encoding: 'utf8', env });
    return r.status === 1 && /entropy-backstop preload/.test(r.stderr) ? 'G45 no-preload start: refused' : `G45 no-preload start: NOT refused (status ${r.status}) ${r.stderr}`;
  } finally { rmSync(d, { recursive: true, force: true }); }
}

function run([label, from, to, expect]) {
  const d = mkdtempSync(join(tmpdir(), 'g39-mut-'));
  try {
    for (const p of ['tools', 'src', 'verification']) cpSync(join(ROOT, p), join(d, p), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(d, 'package.json'));
    const f = join(d, 'tools/ci/entropy-backstop.mjs');
    const s = readFileSync(f, 'utf8');
    if (from !== null) {
      if (!s.includes(from)) return `${label}: anchor missing`;
      writeFileSync(f, s.replace(from, to));
    }
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, ['--import', f, join(d, 'tools/ci/entropy-backstop-check.mjs')], { cwd: d, encoding: 'utf8', timeout: 300_000, env });
    const out = `${r.stdout}\n${r.stderr}`;
    const rw = readyWorld(d);
    const reached = [...[...out.matchAll(/G-(?:39|45) ([a-z0-9-]+) was not rejected/g)].map((m) => m[1]), ...rw].sort();
    if (from === null) return r.status === 0 && rw.length === 0 ? `${label}: clean` : `${label}: NOT CLEAN (status ${r.status}; ${reached.join(', ')})\n${out.slice(-2000)}`;
    if (r.status === 0 && rw.length === 0) return `${label}: SURVIVED`;
    const missing = (expect || []).filter((x) => !reached.includes(x));
    if (missing.length) return `${label}: killed, but expected bypasses not reached: ${missing.join(', ')}`;
    return `${label}: killed${expect ? ` (reached: ${reached.join(', ')})` : ''}`;
  } finally { rmSync(d, { recursive: true, force: true }); }
}

const base = run(['baseline (unmutated tree)', null, null, null]);
console.log(base);
const np = noPreload();
console.log(np);
const lines = [...G39_MUTANTS, ...G45_MUTANTS].map(run);
for (const l of lines) console.log(l);
const bad = lines.filter((l) => !/: killed( \(|$)/.test(l));
if (!/: clean$/.test(base)) bad.push(base);
if (!/: refused$/.test(np)) bad.push(np);
process.exit(bad.length ? 1 : 0);
