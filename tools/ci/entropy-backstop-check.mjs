#!/usr/bin/env node
// check:ph0 hook for the M-162 / G-29 entropy backstop. Must be started with
// `node --import ./tools/ci/entropy-backstop.mjs tools/ci/entropy-backstop-check.mjs`.
// Asserts install, frozen hooks, NODE_OPTIONS inheritance, identity, and
// counters. G-40: identity, per-call and stack checks, counters at exit,
// teardown, fail-closed on no frames, worker hook, entropy-folder, and frozen
// hooks are asserted here so those mutants cannot survive check:ph0 alone. Planted-call coverage for every entry point lives in
// test/entropy-backstop.test.mjs and is also invoked here so a dropped
// caller-check cannot survive check:ph0 alone.

import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MARK, ENTRY_POINT_IDS, getMarker, assertWrappersIntact, assertCountersHealthy, isUnderEntropy } from './entropy-backstop.mjs';

const require = createRequire(import.meta.url);
const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');

const marker = getMarker();
if (!marker || marker.installed !== true || globalThis[MARK] !== marker) {
  console.error('entropy-backstop-check: hooks are not installed');
  process.exit(1);
}
if (marker.entryPointIds.length !== ENTRY_POINT_IDS.length) {
  console.error(`entropy-backstop-check: expected ${ENTRY_POINT_IDS.length} entry points, got ${marker.entryPointIds.length}`);
  process.exit(1);
}
for (const id of ENTRY_POINT_IDS) {
  if (!marker.wrappers?.[id]) {
    console.error(`entropy-backstop-check: missing wrapper for ${id}`);
    process.exit(1);
  }
  const n = marker.countersAtInstall?.[id];
  if (n !== 0) {
    console.error(`entropy-backstop-check: counter ${id} was ${n} at install`);
    process.exit(1);
  }
}
try {
  assertWrappersIntact('check:ph0');
  assertCountersHealthy('check:ph0');
} catch (e) {
  console.error(String(e && e.message));
  process.exit(1);
}
const opt = process.env.NODE_OPTIONS || '';
if (!opt.includes('entropy-backstop.mjs')) {
  console.error('entropy-backstop-check: NODE_OPTIONS does not contain the preload (workers would miss it)');
  process.exit(1);
}

function plantedScript(id) {
  return `import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const c = require('node:crypto');
const buf = new Uint8Array(1);
const id = ${JSON.stringify(id)};
try {
  if (id === 'randomFillSync') c.randomFillSync(buf);
  else if (id === 'randomBytes') c.randomBytes(1);
  else if (id === 'randomInt') c.randomInt(0, 2);
  else if (id === 'randomUUID') c.randomUUID();
  else if (id === 'getRandomValues') c.getRandomValues(buf);
  else if (id === 'webcrypto.getRandomValues') c.webcrypto.getRandomValues(buf);
  else if (id === 'globalThis.crypto.getRandomValues') globalThis.crypto.getRandomValues(buf);
  else if (id === 'Crypto.prototype.getRandomValues') Crypto.prototype.getRandomValues.call(globalThis.crypto, buf);
  else if (id === 'webcrypto.randomUUID') c.webcrypto.randomUUID();
  else if (id === 'subtle.generateKey') c.webcrypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
  else if (id === 'SubtleCrypto.prototype.generateKey') SubtleCrypto.prototype.generateKey.call(c.webcrypto.subtle, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
  else if (id === 'randomFill') c.randomFill(buf, () => {});
  else if (id === 'generateKeySync') c.generateKeySync('hmac', { length: 256 });
  else if (id === 'generateKey') c.generateKey('hmac', { length: 256 }, () => {});
  else if (id === 'generatePrime') c.generatePrime(16, () => {});
  else if (id === 'generatePrimeSync') c.generatePrimeSync(16);
  else if (id === 'generateKeyPair') c.generateKeyPair('ed25519', () => {});
  else if (id === 'generateKeyPairSync') c.generateKeyPairSync('ed25519');
  else if (id === 'ECDH.prototype.generateKeys') {
    const e = c.createECDH('prime256v1');
    Object.getPrototypeOf(e).generateKeys.call(e);
  } else if (id === 'getDiffieHellman') c.getDiffieHellman('modp14');
  else if (id === 'createDiffieHellman') c.createDiffieHellman(256);
  else if (id === 'createDiffieHellmanGroup') c.createDiffieHellmanGroup('modp14');
  else if (id === 'DiffieHellman.prototype.generateKeys') {
    c.DiffieHellman.prototype.generateKeys.call({});
  } else if (id === 'DiffieHellmanGroup.prototype.generateKeys') {
    const g = c.createDiffieHellmanGroup('modp14');
    Object.getPrototypeOf(g).generateKeys.call(g);
  } else if (id === 'randomUUIDv7') c.randomUUIDv7();
  else throw new Error('unknown id ' + id);
  console.error('planted call of ' + id + ' was not rejected');
  process.exit(0);
} catch (e) {
  const msg = String(e && e.message);
  if (/entropy-backstop:/.test(msg)) process.exit(1);
  console.error(msg);
  process.exit(2);
}
`;
}

const dir = mkdtempSync(join(tmpdir(), 'bs-check-'));
let failed = 0;
{
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, '-e', 'console.log("should-not-run")'], {
    cwd: ROOT, encoding: 'utf8', timeout: 20_000,
    env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: '/tmp/should-not-allow' },
  });
  if (r.status === 0 || !/ENTROPY_BACKSTOP_ALLOWED is set/.test(`${r.stderr}\n${r.stdout}`)) {
    console.error(`entropy-backstop-check: ENTROPY_BACKSTOP_ALLOWED did not make the backstop refuse to run (status ${r.status})\n${r.stdout}\n${r.stderr}`);
    failed += 1;
  }
}
try {
  const planted = join(dir, 'src', 'health', 'planted.mjs');
  const allowed = join(dir, 'src', 'entropy', 'ok.mjs');
  mkdirSync(dirname(planted), { recursive: true });
  mkdirSync(dirname(allowed), { recursive: true });
  writeFileSync(allowed, 'export {}\n');
  for (const id of ENTRY_POINT_IDS) {
    writeFileSync(planted, plantedScript(id));
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env },
    });
    if (r.status === 0) {
      console.error(`entropy-backstop-check: planted call of ${id} was not rejected\n${r.stdout}\n${r.stderr}`);
      failed += 1;
    } else if (!/entropy-backstop:/.test(`${r.stderr}\n${r.stdout}`)) {
      console.error(`entropy-backstop-check: planted call of ${id} failed without a backstop message (status ${r.status})\n${r.stdout}\n${r.stderr}`);
      failed += 1;
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

// G-40: these checks run in the check:ph0 backstop step itself, so a mutant
// that no-ops identity / per-call / stack / counters / teardown / fail-closed,
// or that drops the worker hook, widens src/entropy, or leaves hooks writable,
// cannot survive check:ph0 alone.

if (isUnderEntropy(join(ROOT, 'src/mapping/index.ts')) || isUnderEntropy(join(ROOT, 'src/verify/replayRandomBytes.ts'))
  || isUnderEntropy(join(ROOT, 'src/health/cht.ts'))) {
  console.error('entropy-backstop-check: isUnderEntropy accepted a non-entropy src/ path');
  failed += 1;
}

{
  const require = createRequire(import.meta.url);
  const crypto = require('node:crypto');
  const sites = [
    [Crypto.prototype, 'getRandomValues'],
    [crypto, 'randomBytes'],
    [crypto, 'randomFillSync'],
    [crypto, 'randomUUID'],
  ];
  for (const [obj, key] of sites) {
    const pd = Object.getOwnPropertyDescriptor(obj, key);
    if (pd && (pd.writable !== false || pd.configurable !== false)) {
      console.error(`entropy-backstop-check: hook on ${key} is not frozen (writable=${pd.writable}, configurable=${pd.configurable})`);
      failed += 1;
    }
  }
}

{
  const id = 'randomBytes';
  const saved = marker.wrappers[id];
  marker.wrappers[id] = function g40Decoy() {};
  let threw = false;
  try { assertWrappersIntact('g40-identity'); } catch { threw = true; }
  marker.wrappers[id] = saved;
  if (!threw) {
    console.error('entropy-backstop-check: assertWrappersIntact did not throw after a wrapper-identity tamper');
    failed += 1;
  }
}

{
  const saved = marker.counters.randomBytes;
  marker.counters.randomBytes = -1;
  let threw = false;
  try { assertCountersHealthy('g40-counters'); } catch { threw = true; }
  marker.counters.randomBytes = saved;
  if (!threw) {
    console.error('entropy-backstop-check: assertCountersHealthy did not throw after a counter tamper');
    failed += 1;
  }
}

{
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, '-e', "require('node:crypto').randomBytes(1); console.log('G40-NOFRAME-BYTES')"], {
    cwd: ROOT, encoding: 'utf8', timeout: 20_000,
    env: { ...process.env },
  });
  const out = `${r.stdout}\n${r.stderr}`;
  if (r.status === 0 || /G40-NOFRAME-BYTES/.test(out) || !/entropy-backstop:/.test(out)) {
    console.error(`entropy-backstop-check: a call with no user caller frame was not fail-closed (status ${r.status})\n${out}`);
    failed += 1;
  }
}

{
  const plant = join(ROOT, 'src/entropy/_g40_stack_check.mjs');
  writeFileSync(plant, `import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
// Change the saved stack-trace settings without wiping frames, so checkCaller
// still sees the src/entropy path. Per-call identity/stack checks must reject this.
Error.stackTraceLimit = (Error.stackTraceLimit ?? 10) + 1;
try {
  require('node:crypto').randomBytes(1);
  console.error('G40-STACK-CALL-OK');
  process.exit(0);
} catch (e) {
  const msg = String(e && e.message);
  if (/entropy-backstop:/.test(msg)) process.exit(1);
  console.error(msg);
  process.exit(2);
}
`);
  try {
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, plant], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env },
    });
    const out = `${r.stdout}\n${r.stderr}`;
    if (r.status === 0 || /G40-STACK-CALL-OK/.test(out) || !/entropy-backstop:/.test(out)) {
      console.error(`entropy-backstop-check: per-call identity/stack checks did not reject a stack-trace-setting tamper from src/entropy (status ${r.status})\n${out}`);
      failed += 1;
    }
  } finally {
    try { unlinkSync(plant); } catch { /* ignore */ }
  }
}

{
  const dir = mkdtempSync(join(tmpdir(), 'bs-g40-teardown-'));
  const script = join(dir, 'tamper-counters.mjs');
  writeFileSync(script, `const MARK = Symbol.for('open-rng-engine/entropy-backstop/v1');
const m = globalThis[MARK];
if (!m || !m.counters) { console.error('no marker'); process.exit(2); }
m.counters.randomBytes = -1;
`);
  try {
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, script], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env },
    });
    if (r.status === 0) {
      console.error(`entropy-backstop-check: teardown did not fail after a counter tamper (status 0)\n${r.stdout}\n${r.stderr}`);
      failed += 1;
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

{
  const dir = mkdtempSync(join(tmpdir(), 'bs-g40-worker-'));
  const host = join(dir, 'worker-host.mjs');
  writeFileSync(host, `import { Worker } from 'node:worker_threads';
const w = new Worker("require('node:crypto').randomBytes(1); console.log('G40-WORKER-BYTES');", { eval: true, execArgv: [], env: {} });
w.on('error', (e) => { console.error(String(e)); process.exit(2); });
w.on('message', (m) => { console.error('message', m); });
w.on('exit', (code) => process.exit(code === 0 ? 0 : (code || 1)));
`);
  try {
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, host], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env },
    });
    const out = `${r.stdout}\n${r.stderr}`;
    if (r.status === 0 || /G40-WORKER-BYTES/.test(out) || !/entropy-backstop:/.test(out)) {
      console.error(`entropy-backstop-check: worker hook did not reject an eval worker planted call (status ${r.status})\n${out}`);
      failed += 1;
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// G-39: env:{} and NODE_OPTIONS='' must not drop the preload for child_process.
{
  const childDir = mkdtempSync(join(tmpdir(), 'bs-child-'));
  try {
    const childPlant = join(childDir, 'src', 'health', 'child-env.mjs');
    mkdirSync(dirname(childPlant), { recursive: true });
    writeFileSync(childPlant, plantedScript('randomBytes'));
    const launcherFor = (envExpr) => `import { spawnSync } from 'node:child_process';
const r = spawnSync(process.execPath, [${JSON.stringify(childPlant)}], { encoding: 'utf8', timeout: 20000, env: ${envExpr} });
process.stderr.write(String(r.stderr || ''));
process.stdout.write(String(r.stdout || ''));
process.exit(r.status === 0 ? 0 : (/entropy-backstop:/.test(String(r.stderr)+String(r.stdout)) ? 1 : 2));
`;
    for (const [label, envExpr] of [['env-empty', '{}'], ['node-options-empty', "{ ...process.env, NODE_OPTIONS: '' }"]]) {
      const launcher = join(childDir, `launch-${label}.mjs`);
      writeFileSync(launcher, launcherFor(envExpr));
      const r = spawnSync(process.execPath, ['--import', BACKSTOP, launcher], {
        cwd: ROOT, encoding: 'utf8', timeout: 20_000,
        env: { ...process.env },
      });
      if (r.status === 0) {
        console.error(`entropy-backstop-check: child_process ${label} planted call was not rejected\n${r.stdout}\n${r.stderr}`);
        failed += 1;
      } else if (!/entropy-backstop:/.test(`${r.stderr}\n${r.stdout}`)) {
        console.error(`entropy-backstop-check: child_process ${label} failed without a backstop message (status ${r.status})\n${r.stdout}\n${r.stderr}`);
        failed += 1;
      }
    }
  } finally {
    rmSync(childDir, { recursive: true, force: true });
  }
}

if (failed) process.exit(1);
console.log(`entropy-backstop-check: ${ENTRY_POINT_IDS.length} entry points hooked, planted calls rejected, NODE_OPTIONS set, G-40 invariants held`);
process.exit(0);
