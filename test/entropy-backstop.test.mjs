import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, cpSync, rmSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { MARK, ENTRY_POINT_IDS, isExactAllowed, isPrefixAllowed, parseCallerFrames, defaultAllowedCallers } from '../tools/ci/entropy-backstop.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const FIX = join(ROOT, 'test/fixtures/entropy-backstop');

// ---- M-162: hooks must already be installed before this test file loaded,
// and every counter was 0 at install time. A late-install mutant is killed here.
const marker = globalThis[MARK];
if (!marker || marker.installed !== true) {
  throw new Error('entropy-backstop hooks must be installed before any test file loads (M-162 late-install)');
}
for (const id of ENTRY_POINT_IDS) {
  const n = marker.countersAtInstall?.[id];
  if (n !== 0) throw new Error(`entropy-backstop counter ${id} was ${n} at install (must be 0)`);
  if (!marker.wrappers?.[id]) throw new Error(`entropy-backstop missing wrapper for ${id}`);
}
if (marker.entryPointIds.length !== 8) {
  throw new Error(`entropy-backstop must wrap 8 entry points, got ${marker.entryPointIds.join(',')}`);
}

test('M-162: preload marker lists every entry point and wrappers are live identities', () => {
  const require = createRequire(import.meta.url);
  const crypto = require('node:crypto');
  const expected = {
    'randomFillSync': () => crypto.randomFillSync,
    'randomBytes': () => crypto.randomBytes,
    'randomInt': () => crypto.randomInt,
    'getRandomValues': () => crypto.getRandomValues,
    'randomUUID': () => crypto.randomUUID,
    'webcrypto.getRandomValues': () => crypto.webcrypto.getRandomValues,
    'subtle.generateKey': () => crypto.webcrypto.subtle.generateKey,
    'globalThis.crypto.getRandomValues': () => globalThis.crypto.getRandomValues,
  };
  for (const id of ENTRY_POINT_IDS) {
    assert.equal(typeof expected[id](), 'function', id);
    // Node's crypto.getRandomValues is a non-configurable getter that forwards
    // to webcrypto.getRandomValues; identity is tracked on that hook.
    if (id === 'getRandomValues') {
      assert.equal(marker.wrappers[id], marker.wrappers['webcrypto.getRandomValues']);
      assert.equal(crypto.webcrypto.getRandomValues, marker.wrappers[id], 'cjs getRandomValues is hooked via the webcrypto wrapper');
      continue;
    }
    assert.equal(expected[id](), marker.wrappers[id], `${id} live identity must be the stored wrapper`);
  }
});

test('M-162: matching is exact path, not prefix', () => {
  const allowed = [resolve('/repo/src/entropy')];
  const evil = resolve('/repo/src/entropy.evil/call.mjs');
  const child = resolve('/repo/src/entropy/ok.mjs');
  assert.equal(isPrefixAllowed(evil, allowed), true, 'prefix matcher would wrongly accept src/entropy.evil');
  assert.equal(isExactAllowed(evil, allowed), false);
  assert.equal(isExactAllowed(child, allowed), false, 'exact match is file identity, not a directory prefix');
  assert.equal(isExactAllowed(allowed[0], allowed), true);
});

test('M-162: parseCallerFrames skips the backstop itself', () => {
  const self = marker.self;
  const stack = `Error\n    at entropyBackstopWrapped (${self}:1:1)\n    at file:///repo/src/entropy/ok.mjs:2:3\n    at node:internal/main/run_main_module:1:1\n`;
  const frames = parseCallerFrames(stack, { selfPath: self });
  assert.deepEqual(frames, [resolve('/repo/src/entropy/ok.mjs')]);
});

function runChild({ cwd = ROOT, env = {}, script, scriptPath, extraArgs = [] }) {
  const dir = mkdtempSync(join(tmpdir(), 'm162-'));
  const file = scriptPath ?? join(dir, 'script.mjs');
  if (script != null) {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, script);
  }
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, file, ...extraArgs], {
    cwd, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 20_000,
  });
  return { ...r, dir, file };
}

test('M-162: a planted src module (outside src/entropy) calling getRandomValues fails the run', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm162-plant-'));
  try {
    const planted = join(dir, 'src', 'health', 'planted.mjs');
    const allowed = join(dir, 'src', 'entropy', 'ok.mjs');
    mkdirSync(dirname(planted), { recursive: true });
    mkdirSync(dirname(allowed), { recursive: true });
    writeFileSync(planted, readFileSync(join(FIX, 'call-getRandomValues.mjs')));
    writeFileSync(allowed, 'export {}\n');
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: allowed },
    });
    assert.notEqual(r.status, 0, `planted src module must fail:\n${r.stdout}\n${r.stderr}`);
    assert.match(`${r.stderr}\n${r.stdout}`, /entropy-backstop: .*getRandomValues/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('M-162: the same call from src/entropy (exact allowed file) passes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm162-ok-'));
  try {
    const ok = join(dir, 'src', 'entropy', 'ok.mjs');
    mkdirSync(dirname(ok), { recursive: true });
    writeFileSync(ok, readFileSync(join(FIX, 'call-getRandomValues.mjs')));
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, ok], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: ok },
    });
    assert.equal(r.status, 0, `call from src/entropy must pass:\n${r.stdout}\n${r.stderr}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('M-162: an unwrap by code under test fails at teardown', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm162-unwrap-'));
  try {
    const ok = join(dir, 'src', 'entropy', 'unwrap.mjs');
    mkdirSync(dirname(ok), { recursive: true });
    writeFileSync(ok, readFileSync(join(FIX, 'unwrap-getRandomValues.mjs')));
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, ok], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: ok },
    });
    assert.notEqual(r.status, 0, `unwrap must fail:\n${r.stdout}\n${r.stderr}`);
    assert.match(`${r.stderr}\n${r.stdout}`, /unwrapped or re-wrapped/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('M-162: prefix-shaped path src/entropy.evil is rejected under exact matching', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm162-prefix-'));
  try {
    const evil = join(dir, 'src', 'entropy.evil', 'call.mjs');
    const allowedDir = join(dir, 'src', 'entropy');
    mkdirSync(dirname(evil), { recursive: true });
    mkdirSync(allowedDir, { recursive: true });
    writeFileSync(evil, readFileSync(join(FIX, 'call-getRandomValues.mjs')));
    // Even if a mutant used directory-prefix matching, entropy vs entropy.evil is the classic miss.
    // The allowed list is an exact file (not a directory) plus we also pass the directory to show
    // exact-file matching still rejects the evil path.
    const allowedFile = join(allowedDir, 'ok.mjs');
    writeFileSync(allowedFile, 'export {}\n');
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, evil], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: `${allowedFile}:${allowedDir}` },
    });
    assert.notEqual(r.status, 0, `src/entropy.evil must fail exact match:\n${r.stdout}\n${r.stderr}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('M-162: default allowed callers are the explicit src/entropy files', () => {
  const list = defaultAllowedCallers();
  assert.deepEqual(list, [
    resolve(ROOT, 'src/entropy/blockPlan.ts'),
    resolve(ROOT, 'src/entropy/index.ts'),
  ]);
});
