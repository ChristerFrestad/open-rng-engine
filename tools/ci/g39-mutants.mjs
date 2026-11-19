#!/usr/bin/env node
// G-39 mutant runner (HoQ 4c7adda0/f575fe1f §3.4; CTO batch D). Each mutant turns one rule of the child
// policy off in a copy of the tree and runs the real entropy-backstop-check there. It is killed when the
// check fails AND every expected bypass are reported as reached.
// Must run WITHOUT the backstop (`node tools/ci/g39-mutants.mjs`): under it, every node child is forced to
// load this repo's backstop, so a mutated copy can never load alone. That is the policy working, and also
// why this is not part of `npm test`. It is not wired into check:ph0 because package.json is frozen.
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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
  ['G46-M1 process.execve guard off', "  if (typeof process.execve === 'function' && !process.execve._backstopBinding) {", '  if (false) {', ['execve-node', 'execve-sh']],
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
  // G-57 (HoQ HM-22, HM-23, HM-25). HM-24 (realpath-basename check) is subsumed by the G-55 pin: the launch
  // now refuses any real path that is not pinned for that tool name. G57-M3 removes the real-path half of the
  // pin lookup (what HM-24's basename check guarded); RW-symlink-renamed (a symlink named like the tool whose
  // real file is a byte-identical, unpinned copy under another name) kills it. The spawn hook's remaining compare with
  // the pinned real path only guards a swap between the pin check and the spawn, which no fixture can force
  // without a race, so a mutant of it is listed as equivalent.
  ['G57-M1 (HM-22) launch does not re-run the guard', '  grantEntry.assertEvidenceRunReady();\n  if (typeof file', '  if (typeof file', ['RW-ready-flips']],
  ['G57-M2 (HM-23) several tool names allowed in one launch', '&& EVIDENCE_TOOLS.includes(base) && names.length === 1;', '&& EVIDENCE_TOOLS.includes(base);', ['RW-two-tools']],
  ['G57-M3 (HM-24) pin found by tool name only, real path not compared', '  const pin = bins.find((b) => b && b.tool === tool && b.path === real);', '  const pin = bins.find((b) => b && b.tool === tool);', ['RW-unpinned-path', 'RW-symlink-renamed']],
  ['G57-M4 (HM-25) launch does not force shell:false', '{ ...options, shell: false }', '{ shell: false, ...options }', ['RW-shell-forced-off']],
  // G-54 / G-55 / G-60 (HoQ report 505599e..96aaf91).
  ['G54-M1 collector preload check off', "  if (!ev) throw new Error('collector refused: no entropy-backstop preload proof (G-54)');\n", '', ['NP-runner-collect'], 'verification/harness/collector.mjs'],
  ['G54-M2 checkCollected stamp check off', '  if (grant) { const g = grantStampError(result); if (g) f.push(g); }\n', '', ['NP-runner-collect', 'RW-unstamped-in-run'], 'verification/harness/collector.mjs'],
  ['G54-M4 collector grant check off', "  if (!ev.active()) throw new Error('collector refused: no open evidence grant (G-54)');\n", '', ['collect-outside-grant'], 'verification/harness/collector.mjs'],
  ['G54-M5 stamp compared by presence of the field only', 'return t !== null && result.grant === t ? null', "return typeof result.grant === 'string' ? null", ['RW-forged-stamp'], 'verification/harness/collector.mjs'],
  ['G54-M3 result stamped outside a grant', "  if (activeGrant === null || !evidenceGrants.has(activeGrant)) refuseChild('result stamp outside", "  if (false) refuseChild('result stamp outside", ['stamp-outside-grant']],
  ['G55-M1 binary pin check off', '  const real = pinnedBinary(file);\n', '  const real = realpathSync(file);\n', ['RW-unpinned-path', 'RW-pinned-script', 'RW-sha-mismatch', 'RW-bad-source-pin']],
  ['G55-M2 script check off', "  if (bytes.subarray(0, 2).toString('latin1') === '#!') refuseChild", '  if (false) refuseChild', ['RW-pinned-script']],
  ['G55-M3 binary sha check off', "  if (createHash('sha256').update(bytes).digest('hex') !== pin.sha256) refuseChild", '  if (false) refuseChild', ['RW-sha-mismatch']],
  ['G55-M4 source pin not compared with tool-pins', '  if (!src || !pin.source || pin.source.name !== src.name || pin.source.sha256 !== src.sha256) refuseChild', '  if (false) refuseChild', ['RW-bad-source-pin']],
  ['G60-M1 grant left open at exit not reported', "process.on('exit', onGrantLeak);", '', ['RW-open-never-closed']],
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
  ['RW-ready-flips', false, (T) => `globalThis.__g39NotReady = true; launch(${T.DH}, ['-a']);`],
  ['RW-two-tools', false, (T) => `launch(${T.DH}, ['tu01' + '-driver']);`],
  ['RW-shell-forced-off', true, (T) => `const fs = await import('node:fs'); const r = launch(${T.DH}, ['x; touch ' + ${T.MK}], { shell: true }); if (r.error || r.status !== 0 || fs.existsSync(${T.MK})) process.exit(3);`],
  ['RW-unpinned-path', false, (T) => `launch(${T.UP}, ['-a']);`],
  ['RW-symlink-renamed', false, (T) => `launch(${T.SL}, ['-a']);`],
  ['RW-pinned-script', false, (T) => `launch(${T.SC}, ['-a']);`],
  ['RW-sha-mismatch', false, (T) => `launch(${T.SM}, ['-a']);`],
  ['RW-bad-source-pin', false, (T) => `launch(${T.AS}, ['1000']);`],
  ['RW-collect-in-run', true, (T) => `const C = await import(${T.COL}); const k = { id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } }; const res = C.collectCounted(k, () => 1, 5); const f = C.checkCollected(res, k, 5, { floor: false }); if (f.length) { console.error(f.join('; ')); process.exit(3); }`],
  ['RW-unstamped-in-run', false, (T) => `const C = await import(${T.COL}); const k = { id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } }; const f = C.checkCollected(C.collect(k, () => 1, 5), k, 5, { floor: false }); if (f.length) { console.error(f.join('; ')); process.exit(1); }`],
  ['RW-forged-stamp', false, (T) => `const C = await import(${T.COL}); const k = { id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } }; const r = C.collect(k, () => 1, 5); r.grant = 'grant-1@' + process.pid; const f = C.checkCollected(r, k, 5, { floor: false }); if (f.length) { console.error(f.join('; ')); process.exit(1); }`],
  ['RW-open-never-closed', 'G-60', () => '', () => `await globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].evidence.open();`],
];

function readyWorld(d) {
  const reached = [];
  const ee = join(d, 'verification/harness/evidence-entry.mjs');
  const s = readFileSync(ee, 'utf8');
  const from = '  return { ready: df.ready, df };';
  if (!s.includes(from)) return ['RW-anchor-missing'];
  writeFileSync(ee, s.replace(from, '  return { ready: globalThis.__g39NotReady !== true, df };'));
  const bin = join(d, 'rw-bin');
  mkdirSync(bin, { recursive: true });
  const T = {};
  // G-55: the READY world pins its fake binaries (copies of /bin/true) in the copy's tool-binaries.json.
  const srcs = JSON.parse(readFileSync(join(d, 'verification/tool-pins-v1.1.json'), 'utf8')).tools;
  const NAMES = { ['die' + 'harder']: 'Dieharder', ['RNG' + '_test']: 'PractRand', ['ass' + 'ess']: 'NIST STS' };
  const pins = [];
  const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');
  const src = (t) => { const x = srcs.find((y) => y.name === NAMES[t]); return { name: x.name, sha256: x.sha256 }; };
  const put = (k, dir, t, { pin = true, body = null, shaOverride = null, srcOverride = null } = {}) => {
    mkdirSync(join(d, dir), { recursive: true });
    const f = join(d, dir, t);
    if (body === null) copyFileSync(realpathSync('/bin/true'), f); else writeFileSync(f, body);
    chmodSync(f, 0o755);
    if (pin) pins.push({ tool: t, path: realpathSync(f), sha256: shaOverride ?? sha(f), source: srcOverride ?? src(t), build: 'g39 READY world fake (/bin/true copy)' });
    T[k] = JSON.stringify(f);
  };
  put('DH', 'rw-bin', 'die' + 'harder');
  put('PR', 'rw-bin', 'RNG' + '_test');
  put('UP', 'rw-unpinned', 'die' + 'harder', { pin: false });
  put('SC', 'rw-script', 'die' + 'harder', { body: '#!/bin/sh\nexit 0\n' });
  put('SM', 'rw-shamismatch', 'die' + 'harder', { shaOverride: '0'.repeat(64) });
  put('AS', 'rw-badsrc', 'ass' + 'ess', { srcOverride: { name: 'NIST STS', sha256: 'f'.repeat(64) } });
  // HM-24's threat: a path named like the tool that resolves to some other file (here a /bin/true copy named 'sh').
  mkdirSync(join(d, 'rw-symlink'), { recursive: true }); mkdirSync(join(d, 'rw-symtarget'), { recursive: true });
  copyFileSync(realpathSync('/bin/true'), join(d, 'rw-symtarget', 'sh')); chmodSync(join(d, 'rw-symtarget', 'sh'), 0o755);
  symlinkSync(join(d, 'rw-symtarget', 'sh'), join(d, 'rw-symlink', 'die' + 'harder'));
  T.SL = JSON.stringify(join(d, 'rw-symlink', 'die' + 'harder'));
  T.MK = JSON.stringify(join(d, 'rw-shell-mark'));
  T.COL = JSON.stringify(pathToFileURL(join(d, 'verification/harness/collector.mjs')).href);
  writeFileSync(join(d, 'verification/harness/tool-binaries.json'), JSON.stringify({ binaries: pins }, null, 1));
  const bs = join(d, 'tools/ci/entropy-backstop.mjs');
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  for (const [label, green, body, after] of RW_CASES) {
    const f = join(d, `rw-${label}.mjs`);
    writeFileSync(f, `import { spawnSync, execSync } from 'node:child_process';\nconst { startEvidenceRun } = await import(${JSON.stringify(pathToFileURL(ee).href)});\nawait startEvidenceRun(async ({ launch }) => { ${body(T)} });\n${after ? after(T) : ''}\nconsole.log('RW-OK');\n`);
    const r = spawnSync(process.execPath, ['--import', bs, f], { cwd: d, encoding: 'utf8', timeout: 60_000, env });
    const out = `${r.stdout}\n${r.stderr}`;
    const ok = green === 'G-60' ? r.status !== 0 && /\(G-60\)/.test(out)
      : green ? r.status === 0 && /RW-OK/.test(out) : r.status !== 0 && /\(G-(?:45|54|55)\)|harness NOT-READY/.test(out) && !/RW-OK/.test(out);
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

// G-54 (HoQ N15): the exact run HoQ found green. A plain `node runner.mjs` (no preload) spawns a battery
// binary (nothing can stop that in an unhooked process) and then tries to count what it got. The collector
// must refuse, and checkCollected must reject an unstamped result, so nothing from such a run can count.
function npWorld(d) {
  const bin = join(d, 'np-bin');
  mkdirSync(bin, { recursive: true });
  const dh = join(bin, 'die' + 'harder');
  copyFileSync(realpathSync('/bin/true'), dh); chmodSync(dh, 0o755);
  const f = join(d, 'np-runner.mjs');
  writeFileSync(f, `import { spawnSync } from 'node:child_process';
const C = await import(${JSON.stringify(pathToFileURL(join(d, 'verification/harness/collector.mjs')).href)});
const ran = spawnSync(${JSON.stringify(dh)}, ['-a']).status === 0;
const k = { id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } };
let refused = false;
try { C.collectCounted(k, () => 1, 5); } catch (e) { refused = e.message.includes('collector refused: no entropy-backstop preload proof (G-54)'); }
const f = C.checkCollected(C.collect(k, () => 1, 5), k, 5, { floor: false });
const rejected = f.some((x) => x.includes('(G-54)'));
console.log(ran && refused && rejected ? 'NP-REFUSED' : 'NP-NOT-REFUSED ' + JSON.stringify({ ran, refused, f }));
`);
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, [f], { cwd: d, encoding: 'utf8', timeout: 60_000, env });
  return r.status === 0 && /NP-REFUSED/.test(r.stdout) ? [] : ['NP-runner-collect'];
}

function run([label, from, to, expect, file = 'tools/ci/entropy-backstop.mjs']) {
  const d = mkdtempSync(join(tmpdir(), 'g39-mut-'));
  try {
    for (const p of ['tools', 'src', 'verification']) cpSync(join(ROOT, p), join(d, p), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(d, 'package.json'));
    const f = join(d, 'tools/ci/entropy-backstop.mjs');
    const mf = join(d, file);
    const s = readFileSync(mf, 'utf8');
    if (from !== null) {
      if (s.split(from).length !== 2) return `${label}: anchor missing or not unique`;
      writeFileSync(mf, s.replace(from, to));
    }
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, ['--import', f, join(d, 'tools/ci/entropy-backstop-check.mjs')], { cwd: d, encoding: 'utf8', timeout: 300_000, env });
    const out = `${r.stdout}\n${r.stderr}`;
    const rw = [...readyWorld(d), ...npWorld(d)];
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
