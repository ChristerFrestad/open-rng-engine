#!/usr/bin/env node
// G-39 mutant runner (HoQ 4c7adda0/f575fe1f §3.4; CTO batch D). Each mutant turns one rule of the child
// policy off in a copy of the tree and runs the real entropy-backstop-check there. It is killed when the
// check fails AND every expected bypass are reported as reached.
// Must run WITHOUT the backstop (`node tools/ci/g39-mutants.mjs`): under it, every node child is forced to
// load this repo's backstop, so a mutated copy can never load alone. That is the policy working, and also
// why this is not part of `npm test`. It is not wired into check:ph0 because package.json is frozen.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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

function run([label, from, to, expect]) {
  const d = mkdtempSync(join(tmpdir(), 'g39-mut-'));
  try {
    for (const p of ['tools', 'src']) cpSync(join(ROOT, p), join(d, p), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(d, 'package.json'));
    const f = join(d, 'tools/ci/entropy-backstop.mjs');
    const s = readFileSync(f, 'utf8');
    if (!s.includes(from)) return `${label}: anchor missing`;
    writeFileSync(f, s.replace(from, to));
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, ['--import', f, join(d, 'tools/ci/entropy-backstop-check.mjs')], { cwd: d, encoding: 'utf8', timeout: 300_000, env });
    const out = `${r.stdout}\n${r.stderr}`;
    const reached = [...out.matchAll(/G-39 ([a-z0-9-]+) was not rejected/g)].map((m) => m[1]).sort();
    if (r.status === 0) return `${label}: SURVIVED`;
    const missing = (expect || []).filter((x) => !reached.includes(x));
    if (missing.length) return `${label}: killed, but expected bypasses not reached: ${missing.join(', ')}`;
    return `${label}: killed${expect ? ` (reached: ${reached.join(', ')})` : ''}`;
  } finally { rmSync(d, { recursive: true, force: true }); }
}

const lines = G39_MUTANTS.map(run);
for (const l of lines) console.log(l);
const bad = lines.filter((l) => !/: killed( \(|$)/.test(l));
process.exit(bad.length ? 1 : 0);
