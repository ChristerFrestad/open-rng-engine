#!/usr/bin/env node
// A25-2 bare gate run (CTO int-v8 ruling (2) on lockdown test 33). Some cases need a child WITHOUT the backstop
// preload: test 33 of test/a25-lockdown.test.mjs (the lockdown's own dlopen/binding/execve stubs with a stub refuse
// hook: 93/92) and SEC 'one guard'. Under `npm test` (node --import backstop --test) no node child can be bare: the
// G-39 hook puts the preload into every node child and refuses any command that would strip it (that is the security
// property, not a harness bug). So the gate runs these files ONCE MORE from a bare parent, here, with its own log and
// SUMS. Exit 0 only if every test passed with no skip and no todo, and test 33 is reported passed.
// HEAVY enough to need a slot. Usage: node tools/ci/a25-2-bare-gate.mjs --out <new dir>
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
export const BARE_FILES = Object.freeze(['test/a25-lockdown.test.mjs', 'test/r-g64-a25-2-sec.test.mjs']);
const T33 = 'A25-2 direct native/spawn entry points abort, not throw (bare or preloaded)';
const i = process.argv.indexOf('--out');
if (i < 0 || !process.argv[i + 1]) { process.stderr.write('usage: node tools/ci/a25-2-bare-gate.mjs --out <new dir>\n'); process.exit(2); }
if (globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')] || /--(import|require)/.test(process.env.NODE_OPTIONS ?? '') || process.execArgv.length) {
  process.stderr.write('a25-2-bare-gate: this parent is not bare (preload, NODE_OPTIONS or execArgv): refused\n'); process.exit(3);
}
const out = process.argv[i + 1];
mkdirSync(out, { recursive: false });
const env = { ...process.env }; delete env.NODE_OPTIONS;
for (const k of Object.keys(env)) if (k.startsWith('NODE_TEST') || k.startsWith('ENTROPY_BACKSTOP')) delete env[k];
const t0 = new Date();
const r = spawnSync(process.execPath, ['--test', '--test-reporter=spec', ...BARE_FILES], { cwd: ROOT, env, encoding: 'utf8', timeout: 900000, maxBuffer: 1 << 26 });
const t1 = new Date();
const log = r.stdout + r.stderr;
writeFileSync(join(out, 'bare-gate.log'), log, { flag: 'wx' });
const num = (k) => Number((new RegExp(`^ℹ ${k} (\\d+)`, 'm').exec(log) || [])[1] ?? -1);
const res = { files: BARE_FILES, node: process.version, start: t0.toISOString(), end: t1.toISOString(), exit: r.status, signal: r.signal,
  pass: num('pass'), fail: num('fail'), skipped: num('skipped'), todo: num('todo'),
  t33_passed: log.split('\n').some((l) => l.includes(T33) && /^\s*✔/.test(l)) };
res.ok = res.exit === 0 && res.pass > 0 && res.fail === 0 && res.skipped === 0 && res.todo === 0 && res.t33_passed;
writeFileSync(join(out, 'result.json'), JSON.stringify(res, null, 1) + '\n', { flag: 'wx' });
const sums = readdirSync(out).sort().map((f) => `${createHash('sha256').update(readFileSync(join(out, f))).digest('hex')}  ${f}`).join('\n') + '\n';
writeFileSync(join(out, 'SHA256SUMS'), sums, { flag: 'wx' });
process.stdout.write(`${JSON.stringify(res)}\n`);
process.exit(res.ok ? 0 : 1);
