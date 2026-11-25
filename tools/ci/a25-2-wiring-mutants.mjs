#!/usr/bin/env node
// A25-2 wiring mutants M39–M49 (Backend). Each mutant is one exact, single-occurrence text edit in a copy of the
// tracked tree; it is KILLED when its named test(s) fail on the copy. HEAVY (one process tree per mutant): run only in a
// HoQ slot (Addendum A). `--dry` is light: it only checks that every edit applies exactly once on this tree.
// Usage: node tools/ci/a25-2-wiring-mutants.mjs [--dry] [--only M39,M40]
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
const BS = 'tools/ci/entropy-backstop.mjs', SL = 'verification/harness/stream-launcher.mjs';
const W = 'test/r-g64-a25-2-wiring.test.mjs', ST = 'test/r-g64-stream.test.mjs';
export const MUTANTS = Object.freeze([
  { id: 'M39', what: 'lateHookUsed never set (CTO 22:14 ruling 1c)', file: BS, from: '    lateHookUsed = true;\n', to: '\n', test: [W, 'W-late\\(a\\)'] },
  { id: 'M40', what: 'mainIsHelper always true (CTO 22:14 ruling 1c)', file: BS, from: "const mainIsHelper = MAIN_URL !== null && VIEW.entries.has(HELPER_MAIN_REL) && MAIN_URL === pathToFileURL(join(VIEW.root, HELPER_MAIN_REL)).href;", to: 'const mainIsHelper = true;', test: [W, 'W-late\\(b\\)'] },
  { id: 'M41', what: 'late resolve hook result not checked for forbidden builtins', file: BS, from: "      if (r.url.startsWith('node:')) builtinLoadCheck(r.url, 'late resolve');\n", to: '', test: [W, '^W1:'] },
  { id: 'M42', what: 'late load hook bytes not held to the manifest', file: BS, from: "if (createHash('sha256').update(src).digest('hex') !== VIEW.entries.get(v.rel)) helperAbort(EXIT_A25_MANIFEST_DIGEST, `late load:", to: "if (false) helperAbort(EXIT_A25_MANIFEST_DIGEST, `late load:", test: [W, 'W1 \\(load side\\)'] },
  { id: 'M43', what: 'module.register left unguarded', file: BS, from: "  Object.defineProperty(nodeModule, 'register', { value: lateRegister, writable: false, configurable: false, enumerable: true });\n", to: '', test: [W, 'W-late\\(c\\)'] },
  { id: 'M44', what: 'advisory manifest sha not compared with the grant digest', file: BS, from: 'if (HELPER_MODE && ADVISORY_SHA256 !== null && ADVISORY_SHA256 !== MANIFEST_SHA256) {', to: 'if (false) {', test: [ST, 'advisory'] },
  { id: 'M45', what: 'proof manifest_sha256 not compared in the launcher', file: SL, from: 'else if (ctx.helperExpect.manifest_sha256 !== null && pr.manifest_sha256 !== ctx.helperExpect.manifest_sha256)', to: 'else if (false)', test: [ST, '^W6'] },
  { id: 'M47', what: 'manifest file digest not compared with the grant digest (swapped manifest passes)', file: 'tools/ci/a25-manifest.mjs', from: "  if (sha(bytes) !== expectedSha) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'manifest file digest differs from the bound digest' };\n", to: '', test: [W, '^W4:'] },
  { id: 'M48', what: 'lockdown not installed in helper mode', file: BS, from: '  installLockdown({ isManifestUrl: makeIsManifestUrl(VIEW, A25_DYNAMIC_BUILTINS), abort: helperAbort, registerRefuseHook });\n', to: '', test: [W, 'W1c'] },
  { id: 'M49', what: "scheme check skips data: (CTO 22:20 ruling c)", file: BS, from: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('file:')", to: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('data:') || u.startsWith('file:')", test: [W, 'W-scheme'] },
  { id: 'M46', what: 'registerRefuseHook not one-shot', file: BS, from: "  if (REFUSE_HOOK !== null || typeof fn !== 'function') {", to: "  if (typeof fn !== 'function') {", test: [W, '^W2:'] },
]);

const only = (() => { const i = process.argv.indexOf('--only'); return i > 0 ? new Set(process.argv[i + 1].split(',')) : null; })();
const list = MUTANTS.filter((m) => !only || only.has(m.id));
let bad = 0;
for (const m of list) {
  const n = readFileSync(join(ROOT, m.file), 'utf8').split(m.from).length - 1;
  if (n !== 1) { bad++; process.stdout.write(`${m.id} BAD-EDIT: 'from' occurs ${n}x in ${m.file}\n`); }
}
if (bad) process.exit(2);
if (process.argv.includes('--dry')) { process.stdout.write(`dry: ${list.length} edits apply exactly once\n`); process.exit(0); }

const files = spawnSync('git', ['-C', ROOT, 'ls-files', '-co', '--exclude-standard'], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
const results = [];
for (const m of list) {
  const d = mkdtempSync(join(tmpdir(), `a25m-${m.id}-`));
  try {
    for (const f of files) { mkdirSync(dirname(join(d, f)), { recursive: true }); copyFileSync(join(ROOT, f), join(d, f)); }
    const p = join(d, m.file);
    writeFileSync(p, readFileSync(p, 'utf8').replace(m.from, m.to));
    const env = { ...process.env }; delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, ['--test', '--test-name-pattern', m.test[1], m.test[0]], { cwd: d, env, encoding: 'utf8', timeout: 300000 });
    const pass = Number((/^ℹ pass (\d+)/m.exec(r.stdout) || [])[1] ?? -1), fail = Number((/^ℹ fail (\d+)/m.exec(r.stdout) || [])[1] ?? -1);
    const verdict = pass + fail <= 0 ? 'NO-TESTS' : fail > 0 ? 'KILLED' : 'SURVIVED';
    results.push({ id: m.id, what: m.what, verdict, pass, fail });
    process.stdout.write(`${m.id} ${verdict} (pass ${pass}, fail ${fail}) ${m.what}\n`);
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const killed = results.filter((r) => r.verdict === 'KILLED').length;
process.stdout.write(`${killed}/${results.length} killed\n`);
process.exit(killed === results.length ? 0 : 1);
