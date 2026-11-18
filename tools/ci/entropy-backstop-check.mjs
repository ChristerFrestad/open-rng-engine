#!/usr/bin/env node
// check:ph0 hook for the M-162 / G-29 entropy backstop. Must be started with
// `node --import ./tools/ci/entropy-backstop.mjs tools/ci/entropy-backstop-check.mjs`.
// Asserts install, frozen hooks, NODE_OPTIONS inheritance, identity, and
// counters. Planted-call coverage for every entry point lives in
// test/entropy-backstop.test.mjs and is also invoked here so a dropped
// caller-check cannot survive check:ph0 alone.

import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MARK, ENTRY_POINT_IDS, getMarker, assertWrappersIntact, assertCountersHealthy } from './entropy-backstop.mjs';

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
  } else throw new Error('unknown id ' + id);
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

if (failed) process.exit(1);
console.log(`entropy-backstop-check: ${ENTRY_POINT_IDS.length} entry points hooked, planted calls rejected, NODE_OPTIONS set`);
process.exit(0);
