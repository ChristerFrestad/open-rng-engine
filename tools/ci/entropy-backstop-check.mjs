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
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync, unlinkSync, copyFileSync, chmodSync, realpathSync } from 'node:fs';
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
  else if (id === 'createDiffieHellman') c.createDiffieHellman(512);
  else if (id === 'createDiffieHellmanGroup') c.createDiffieHellmanGroup('modp14');
  else if (id === 'DiffieHellman.prototype.generateKeys') {
    c.DiffieHellman.prototype.generateKeys.call({});
  } else if (id === 'DiffieHellmanGroup.prototype.generateKeys') {
    const g = c.createDiffieHellmanGroup('modp14');
    Object.getPrototypeOf(g).generateKeys.call(g);
  } else if (id === 'randomUUIDv7') c.randomUUIDv7();
  else if (id === 'DiffieHellman') new c.DiffieHellman(512).getPrime();
  else if (id === 'DiffieHellmanGroup') new c.DiffieHellmanGroup('modp14').generateKeys();
  else if (id === 'Crypto.prototype.randomUUID') Object.getPrototypeOf(globalThis.crypto).randomUUID.call(globalThis.crypto);
  else if (id === 'publicEncrypt') c.publicEncrypt(c.createPublicKey({ key: {"kty": "RSA", "n": "13xrz0QHLARQc2lIEPi7ZenbAIiRKw_9Fl9GDMqMfAw-jWXtwbySTssIn0H0Rpw4JOyQCJONvk-efonp-N4RMosNwARU5atL6wmmk3tGYJAGcReufg9Z7lcvxmIqCq_JKDomU4oA0bDuqF3kjkeYEFI4795qmKCtrvUmJbF0ISM", "e": "AQAB"}, format: 'jwk' }), buf);
  else if (id === 'sign') c.sign('sha256', buf, c.createPrivateKey({ key: {"kty": "EC", "x": "CXQPEZB9jjf6C-OahpjHmw_lbBJkiuQyG9KMdjX3yf4", "y": "Gxd1Iz-M8isUJg_HtUpfC2jza0wwFc0tCESHRtMpkNk", "crv": "P-256", "d": "_kfrbwFvV1Kfev2MWV0PdejJD4dIYlLgtdJwpLVa6p8"}, format: 'jwk' }));
  else if (id === 'Sign.prototype.sign') c.createSign('sha256').update(buf).sign(c.createPrivateKey({ key: {"kty": "EC", "x": "CXQPEZB9jjf6C-OahpjHmw_lbBJkiuQyG9KMdjX3yf4", "y": "Gxd1Iz-M8isUJg_HtUpfC2jza0wwFc0tCESHRtMpkNk", "crv": "P-256", "d": "_kfrbwFvV1Kfev2MWV0PdejJD4dIYlLgtdJwpLVa6p8"}, format: 'jwk' }));
  else if (id === 'SubtleCrypto.prototype.encrypt') SubtleCrypto.prototype.encrypt.call(c.webcrypto.subtle, { name: 'RSA-OAEP' }, null, buf);
  else if (id === 'SubtleCrypto.prototype.sign') SubtleCrypto.prototype.sign.call(c.webcrypto.subtle, { name: 'ECDSA', hash: 'SHA-256' }, null, buf);
  else if (id === 'SubtleCrypto.prototype.wrapKey') SubtleCrypto.prototype.wrapKey.call(c.webcrypto.subtle, 'raw', null, null, { name: 'RSA-OAEP' });
  else if (id === 'subtle.encrypt') c.webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, null, buf);
  else if (id === 'subtle.sign') c.webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, null, buf);
  else if (id === 'subtle.wrapKey') c.webcrypto.subtle.wrapKey('raw', null, null, { name: 'RSA-OAEP' });
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

// G-39 residual (HoQ a43a432c): (a) an intermediate env/shell that strips NODE_OPTIONS is refused;
// (b) a decoy NODE_OPTIONS that only names the file does not stop injection; (e) a changed marker
// identity is caught per call and at exit.
{
  const d = mkdtempSync(join(tmpdir(), 'bs-g39r-'));
  try {
    const childPlant = join(d, 'src', 'health', 'child.mjs');
    mkdirSync(dirname(childPlant), { recursive: true });
    writeFileSync(childPlant, plantedScript('randomBytes'));
    const decoyDir = join(d, 'decoy');
    mkdirSync(decoyDir, { recursive: true });
    const decoy = join(decoyDir, 'entropy-backstop.mjs');
    writeFileSync(decoy, 'export {};\n');
    const node = JSON.stringify(process.execPath);
    const cp = JSON.stringify(childPlant);
    const cases = [
      ['sh-env-u', `import { spawnSync } from 'node:child_process';
const r = spawnSync('sh', ['-c', 'env -u NODE_OPTIONS ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['env-i', `import { spawnSync } from 'node:child_process';
const r = spawnSync('env', ['-i', ${node}, ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['exec-node-options-empty', `import { execSync } from 'node:child_process';
execSync('NODE_OPTIONS= ' + ${node} + ' ' + ${cp}, { encoding: 'utf8', stdio: 'pipe' });
process.exit(0);`],
      ['decoy-title', `import { spawnSync } from 'node:child_process';
const r = spawnSync(${node}, [${cp}], { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: '--title=entropy-backstop.mjs' } });
process.stderr.write(String(r.stderr || '')); process.stdout.write(String(r.stdout || ''));
process.exit(r.status === 0 ? 0 : (/entropy-backstop:/.test(String(r.stderr) + String(r.stdout)) ? 1 : 2));`],
      ['decoy-import', `import { spawnSync } from 'node:child_process';
const r = spawnSync(${node}, [${cp}], { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: '--import ' + ${JSON.stringify(decoy)} } });
process.stderr.write(String(r.stderr || '')); process.stdout.write(String(r.stdout || ''));
process.exit(r.status === 0 ? 0 : (/entropy-backstop:/.test(String(r.stderr) + String(r.stdout)) ? 1 : 2));`],
      // G-39 at the source (HoQ 4c7adda0/f575fe1f §3.4): HoQ's 8 bypasses, each must be refused.
      ['hoq-1-export-n', `import { spawnSync } from 'node:child_process';
const r = spawnSync('bash', ['-c', 'export -n NODE_OPTIONS; ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-2-unset-indirect', `import { spawnSync } from 'node:child_process';
const r = spawnSync('bash', ['-c', 'N=NODE_OPTIONS; unset $N; ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-3-exec-c', `import { spawnSync } from 'node:child_process';
const r = spawnSync('bash', ['-c', 'exec -c ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-4-script-file', `import { spawnSync } from 'node:child_process';
import { writeFileSync, chmodSync } from 'node:fs';
const f = ${JSON.stringify(join(d, 'x.sh'))};
writeFileSync(f, '#!/bin/sh\\nunset NODE_OPTIONS; exec ' + ${node} + ' ' + ${cp} + '\\n'); chmodSync(f, 0o755);
const r = spawnSync(f, [], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-5-python', `import { spawnSync } from 'node:child_process';
const r = spawnSync('python3', ['-c', "import os; os.environ.pop('NODE_'+'OPTIONS'); os.execv(" + JSON.stringify(${node}) + ", [" + JSON.stringify(${node}) + ", " + JSON.stringify(${cp}) + "])"], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-6-perl', `import { spawnSync } from 'node:child_process';
const r = spawnSync('perl', ['-e', 'delete $ENV{NODE_OPTIONS}; exec(' + JSON.stringify(${node}) + ', ' + JSON.stringify(${cp}) + ')'], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-7-env-printf', `import { spawnSync } from 'node:child_process';
const r = spawnSync('sh', ['-c', 'env $(printf NODE_%s= OPTIONS) ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['hoq-8-declare-x', `import { spawnSync } from 'node:child_process';
const r = spawnSync('bash', ['-c', 'declare +x NODE_OPTIONS; ' + ${node} + ' ' + ${cp}], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      // Variants of the same classes through the other entry points, and two found while fixing.
      ['shell-option-true', `import { spawnSync } from 'node:child_process';
const r = spawnSync('unset NODE_OPTIONS; ' + ${node} + ' ' + ${cp}, { shell: true, encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['exec-sync-shell', `import { execSync } from 'node:child_process';
execSync('bash -c "unset NODE_OPTIONS; ' + ${node} + ' ' + ${cp} + '"', { stdio: 'pipe' });
process.exit(0);`],
      ['exec-file-perl', `import { execFileSync } from 'node:child_process';
execFileSync('/usr/bin/perl', ['-e', 'delete $ENV{NODE_OPTIONS}; exec(' + JSON.stringify(${node}) + ', ' + JSON.stringify(${cp}) + ')'], { stdio: 'pipe' });
process.exit(0);`],
      ['fork-execpath', `import { fork } from 'node:child_process';
const c = fork(${cp}, [], { execPath: '/bin/sh', stdio: 'pipe' });
c.on('exit', (code) => process.exit(code === 0 ? 0 : 2));`],
      ['binding-spawn-sync', `const b = process.binding('spawn_sync');
const r = b.spawn({ file: ${node}, args: [${node}, ${cp}], envPairs: [], stdio: [{ type: 'pipe', readable: true }, { type: 'pipe', writable: true }, { type: 'pipe', writable: true }] });
process.exit(r.status === 0 ? 0 : 2);`],
      ['execve-node', `if (typeof process.execve !== 'function') { console.error('entropy-backstop: process.execve absent on this Node'); process.exit(1); }
const env = { ...process.env }; delete env.NODE_OPTIONS;
process.execve(${node}, [${node}, ${cp}], env);`],
      ['execve-sh', `if (typeof process.execve !== 'function') { console.error('entropy-backstop: process.execve absent on this Node'); process.exit(1); }
process.execve('/bin/sh', ['/bin/sh', '-c', 'unset NODE_OPTIONS; ' + ${node} + ' ' + ${cp}], {});`],
      ['dlopen', `import { createRequire } from 'node:module';
const m = { exports: {} };
try { process.dlopen(m, '/nonexistent/addon.node'); } catch (e) { if (/entropy-backstop:/.test(String(e && e.message))) throw e; }
process.exit(0);`],
      ['shell-chain-after-allowed', `import { execSync } from 'node:child_process';
execSync('mkdir -p ' + ${JSON.stringify(join(d, 'mk'))} + ' && perl -e ' + "'" + 'delete $ENV{NODE_OPTIONS}; exec(' + JSON.stringify(${node}) + ', ' + JSON.stringify(${cp}) + ')' + "'", { stdio: 'pipe' });
process.exit(0);`],
      ['git-alias', `import { spawnSync } from 'node:child_process';
const r = spawnSync('git', ['-c', 'alias.x=!unset NODE_OPTIONS; ' + ${node} + ' ' + ${cp}, 'x'], { encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['git-repo-config', `import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
const g = ${JSON.stringify(join(d, 'gr'))};
mkdirSync(g + '/.git', { recursive: true });
spawnSync('git', ['init', '-q'], { cwd: g });
writeFileSync(g + '/.git/config', '[core]\\n\\tpager = unset NODE_OPTIONS; node x\\n');
const r = spawnSync('git', ['status'], { cwd: g, encoding: 'utf8' });
process.stderr.write(String(r.stderr || '')); process.exit(r.status === 0 ? 0 : 2);`],
      ['git-subcommand', `import { spawnSync } from 'node:child_process';
const r = spawnSync('git', ['difftool', '-x', 'sh'], { encoding: 'utf8' });
process.exit(r.status === 0 ? 0 : 2);`],
      // Proof of preload: a node child that never loads the backstop has no proof and is red, even
      // though it draws nothing (fail-closed: no marker = red).
      ['proof-missing-sync', `import { spawnSync } from 'node:child_process';
spawnSync(process.execPath, ['--version'], { encoding: 'utf8' });
process.exit(0);`],
      ['proof-missing-async', `import { spawn } from 'node:child_process';
spawn(process.execPath, ['--version'], { stdio: 'ignore' });`],
      ['marker-break-call', `import { breakMarkerIdentityForTestOnly } from ${JSON.stringify(pathToFileURL(BACKSTOP).href)};
import { createRequire } from 'node:module';
breakMarkerIdentityForTestOnly();
try { createRequire(import.meta.url)('node:crypto').randomUUID(); console.error('G39-MARKER-CALL-OK'); process.exit(0); }
catch (e) { const m = String(e && e.message); console.error(m); process.exit(/marker identity changed/.test(m) ? 1 : 2); }`],
      ['marker-break-exit', `import { breakMarkerIdentityForTestOnly } from ${JSON.stringify(pathToFileURL(BACKSTOP).href)};
breakMarkerIdentityForTestOnly();`],
    ];
    for (const [label, src] of cases) {
      const file = label.startsWith('marker-') ? join(ROOT, 'src/entropy', `_g39_${label}.mjs`) : join(d, `launch-${label}.mjs`);
      writeFileSync(file, src);
      try {
        const r = spawnSync(process.execPath, ['--import', BACKSTOP, file], { cwd: ROOT, encoding: 'utf8', timeout: 20_000, env: { ...process.env } });
        const out = `${r.stdout}\n${r.stderr}`;
        if (r.status === 0 || /G39-MARKER-CALL-OK/.test(out)) {
          console.error(`entropy-backstop-check: G-39 ${label} was not rejected\n${out}`);
          failed += 1;
        } else if (!/entropy-backstop:/.test(out)) {
          console.error(`entropy-backstop-check: G-39 ${label} failed without a backstop message (status ${r.status})\n${out}`);
          failed += 1;
        }
      } finally { if (label.startsWith('marker-')) { try { unlinkSync(file); } catch { /* ignore */ } } }
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
}

// G-45 (HoQ report c9d7c93..dbd4e00, addendum 1 A7): the evidence entry guard is enforced at the spawn
// layer. HoQ's 8 EG-3 evasions plus the verification/ exemption and HM-17/18 variants: every one must be
// refused BY THE G-45 RULE (its message), not merely by some other rule. The positive path (a grant opened
// by an OK guard) can only exist in a READY tree, so it is exercised by tools/ci/g39-mutants.mjs.
export const G45_CASES = [];
{
  const d = mkdtempSync(join(tmpdir(), 'bs-g45-'));
  try {
    const bin = join(d, 'bin');
    mkdirSync(bin, { recursive: true });
    const TOOLS = ['die' + 'harder', 'tu01' + '-driver', 'ass' + 'ess', 'RNG' + '_test'];
    for (const t of TOOLS) { copyFileSync(realpathSync('/bin/true'), join(bin, t)); chmodSync(join(bin, t), 0o755); }
    const [DH, TU, AS, PR] = TOOLS.map((t) => JSON.stringify(join(bin, t)));
    const EV = JSON.stringify(pathToFileURL(join(ROOT, 'verification/harness/evidence-entry.mjs')).href);
    const head = `import { spawnSync, execSync, execFileSync, exec } from 'node:child_process';\nimport * as cp from 'node:child_process';\nimport path from 'node:path';\n`;
    const tail = `\nprocess.exit(0);\n`;
    const cases = [
      ['indirect-bin', `const BIN = ${DH};\nspawnSync(BIN, ['-a']);`],
      ['path-join-arg', `spawnSync(path.join(${JSON.stringify(bin)}), ['${TOOLS[0]}', '-a']);`],
      ['python-subprocess', `spawnSync('python3', ['-c', "import subprocess; subprocess.run(['${TOOLS[0]}', '-a'])"]);`],
      ['guard-in-comment', `// assertEvidenceRunReady();\nspawnSync(${DH}, ['-a']);`],
      ['dead-guard', `const { assertEvidenceRunReady } = await import(${EV});\nif (false) assertEvidenceRunReady();\nspawnSync(${DH}, ['-a']);`],
      ['swallowed-guard', `const { assertEvidenceRunReady } = await import(${EV});\ntry { assertEvidenceRunReady(); } catch { /* swallowed */ }\nspawnSync(${TU}, ['BigCrush']);`],
      ['guard-in-string', `const g = 'assertEvidenceRunReady(';\nspawnSync(${DH}, [g]);`],
      ['bracket-spawn', `cp['spawn'](${DH}, ['-a']);`],
      ['verification-dir', `spawnSync(${TU}, ['BigCrush', 'raw']);`, 'verification/harness'],
      ['exec-sync', `execSync(${DH} + ' -a');`],
      ['exec-async', `exec('${TOOLS[3]} stdin32');`],
      ['rng-test', `execFileSync(${PR}, ['stdin32']);`],
      ['assess-relative', `spawnSync('./${TOOLS[2]}', ['1000000'], { cwd: ${JSON.stringify(bin)} });`],
      ['sh-c-tool', `spawnSync('sh', ['-c', '${TOOLS[0]} -a']);`],
      ['env-tool', `spawnSync('env', ['${TOOLS[0]}', '-a']);`],
      ['python-plain', `spawnSync('python3', ['-c', 'print(1)']);`],
      ['grant-not-ready', `const ev = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].evidence;\ntry { await ev.open(); } catch (e) { console.error(String(e.message)); process.exit(1); }`],
      ['launch-without-grant', `const ev = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].evidence;\nev.launch(Object.freeze({ grant: 1 }), ${DH}, ['-a']);`],
      ['stamp-outside-grant', `const ev = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].evidence;\nev.stamp({ n: 1 });`],
      ['collect-outside-grant', `const C = await import(${JSON.stringify(pathToFileURL(join(ROOT, 'verification/harness/collector.mjs')).href)});\ntry { C.collectCounted({ id: 'x', primitive: 'randomInt', n_unit: 'value', parameters: { min: 0, max: 2 } }, () => 1, 3); } catch (e) { if (e.message.includes('collector refused: no open evidence grant (G-54)')) { console.error(e.message); process.exit(1); } }`],
      ['start-run-not-ready', `const { startEvidenceRun } = await import(${EV});\nlet ran = false;\ntry { await startEvidenceRun(async ({ launch }) => { ran = true; launch(${DH}, ['-a']); }); } catch (e) { console.error(String(e.message)); process.exit(ran ? 0 : 1); }`],
    ];
    for (const [label, body, sub] of cases) {
      G45_CASES.push(label);
      const dir = sub ? join(d, sub) : d;
      mkdirSync(dir, { recursive: true });
      const file = join(dir, `g45-${label}.mjs`);
      writeFileSync(file, head + body + tail);
      const r = spawnSync(process.execPath, ['--import', BACKSTOP, file], { cwd: ROOT, encoding: 'utf8', timeout: 20_000, env: { ...process.env } });
      const out = `${r.stdout}\n${r.stderr}`;
      if (r.status === 0 || !/\(G-(?:45|54)\)|harness NOT-READY/.test(out)) {
        console.error(`entropy-backstop-check: G-45 ${label} was not rejected by the G-45 rule (status ${r.status})\n${out}`);
        failed += 1;
      }
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
}

if (failed) process.exit(1);
console.log(`entropy-backstop-check: ${ENTRY_POINT_IDS.length} entry points hooked, planted calls rejected, NODE_OPTIONS set, G-40 invariants held, ${G45_CASES.length} G-45 evasions refused at the spawn layer`);
process.exit(0);
