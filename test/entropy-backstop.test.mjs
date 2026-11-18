import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, cpSync, rmSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { MARK, ENTRY_POINT_IDS, isExactAllowed, isPrefixAllowed, parseCallerFrames, defaultAllowedCallers, innermostSrcFrame, isUnderEntropy, isUnderRepoSrc } from '../tools/ci/entropy-backstop.mjs';

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
if (marker.entryPointIds.length !== ENTRY_POINT_IDS.length) {
  throw new Error(`entropy-backstop must wrap ${ENTRY_POINT_IDS.length} entry points, got ${marker.entryPointIds.join(',')}`);
}
if (ENTRY_POINT_IDS.length < 14) {
  throw new Error(`G-29: expected the expanded entry-point list, got ${ENTRY_POINT_IDS.length}`);
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
  for (const [id, getter] of Object.entries(expected)) {
    assert.equal(typeof getter(), 'function', id);
    if (id === 'getRandomValues') {
      // Non-configurable getter: identity is aliased to a hook on the prototype or webcrypto.
      assert.ok(marker.wrappers[id] === marker.wrappers['webcrypto.getRandomValues']
        || marker.wrappers[id] === marker.wrappers['Crypto.prototype.getRandomValues'],
        'cjs getRandomValues is hooked via the webcrypto or prototype wrapper');
      continue;
    }
    assert.equal(getter(), marker.wrappers[id], `${id} live identity must be the stored wrapper`);
  }
  for (const id of ENTRY_POINT_IDS) {
    assert.equal(typeof marker.wrappers[id], 'function', `wrapper missing for ${id}`);
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

test('G-29: hooks are frozen; an unwrap attempt does not let a planted call through', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm162-unwrap-'));
  try {
    const planted = join(dir, 'src', 'health', 'unwrap.mjs');
    const allowed = join(dir, 'src', 'entropy', 'ok.mjs');
    mkdirSync(dirname(planted), { recursive: true });
    mkdirSync(dirname(allowed), { recursive: true });
    writeFileSync(allowed, 'export {}\n');
    writeFileSync(planted, readFileSync(join(FIX, 'unwrap-getRandomValues.mjs')));
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: allowed },
    });
    assert.notEqual(r.status, 0, `unwrap + planted call must fail:\n${r.stdout}\n${r.stderr}`);
    assert.match(`${r.stderr}\n${r.stdout}`, /entropy-backstop:/);
    assert.doesNotMatch(`${r.stderr}\n${r.stdout}`, /call ok/);
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

const PLANTED_CALL = (id) => `import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const c = require('node:crypto');
const buf = new Uint8Array(1);
const id = ${JSON.stringify(id)};
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
`;

for (const id of ENTRY_POINT_IDS) {
  test(`G-29 / M-166: planted src/health call of ${id} is rejected`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'm166-plant-'));
    try {
      const planted = join(dir, 'src', 'health', 'planted.mjs');
      const allowed = join(dir, 'src', 'entropy', 'ok.mjs');
      mkdirSync(dirname(planted), { recursive: true });
      mkdirSync(dirname(allowed), { recursive: true });
      writeFileSync(planted, PLANTED_CALL(id));
      writeFileSync(allowed, 'export {}\n');
      const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
        cwd: ROOT, encoding: 'utf8', timeout: 20_000,
        env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: allowed },
      });
      assert.notEqual(r.status, 0, `planted ${id} must fail:\n${r.stdout}\n${r.stderr}`);
      assert.match(`${r.stderr}\n${r.stdout}`, /entropy-backstop:/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test('G-29: innermost repo src/ frame must be in src/entropy/; outer src frames are allowed', () => {
  const entropy = resolve(ROOT, 'src/entropy/index.ts');
  const index = resolve(ROOT, 'src/index.ts');
  const health = resolve(ROOT, 'src/health/cht.ts');
  const testFile = resolve(ROOT, 'test/entropy-backstop.test.mjs');
  assert.equal(innermostSrcFrame([entropy, index, testFile]), entropy);
  assert.equal(isUnderEntropy(innermostSrcFrame([entropy, index])), true);
  assert.equal(isUnderRepoSrc(index), true);
  assert.equal(isUnderEntropy(innermostSrcFrame([health, index])), false);
  assert.equal(innermostSrcFrame([testFile]), null);
});

test('G-29: Error.prepareStackTrace spoofing is rejected on a wrapped call', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm166-spoof-'));
  try {
    const planted = join(dir, 'src', 'health', 'spoof.mjs');
    const allowed = join(dir, 'src', 'entropy', 'ok.mjs');
    mkdirSync(dirname(planted), { recursive: true });
    mkdirSync(dirname(allowed), { recursive: true });
    writeFileSync(allowed, 'export {}\n');
    writeFileSync(planted, `import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
Error.prepareStackTrace = () => 'Error\\n    at f (${allowed}:1:1)';
require('node:crypto').randomBytes(1);
`);
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env, ENTROPY_BACKSTOP_ALLOWED: allowed },
    });
    assert.notEqual(r.status, 0, `prepareStackTrace spoof must fail:\n${r.stdout}\n${r.stderr}`);
    assert.match(`${r.stderr}\n${r.stdout}`, /prepareStackTrace|entropy-backstop:/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('G-29: a worker inherits the preload via NODE_OPTIONS and rejects a planted call', () => {
  const dir = mkdtempSync(join(tmpdir(), 'm166-worker-'));
  try {
    const planted = join(dir, 'src', 'health', 'worker-host.mjs');
    mkdirSync(dirname(planted), { recursive: true });
    writeFileSync(planted, `
import { Worker } from 'node:worker_threads';
const w = new Worker("require('node:crypto').randomBytes(1);", { eval: true });
w.on('error', (e) => { console.error(String(e)); process.exit(2); });
w.on('exit', (code) => process.exit(code === 0 ? 0 : (code || 1)));
`);
    const r = spawnSync(process.execPath, ['--import', BACKSTOP, planted], {
      cwd: ROOT, encoding: 'utf8', timeout: 20_000,
      env: { ...process.env },
    });
    assert.notEqual(r.status, 0, `worker planted call must fail:\n${r.stdout}\n${r.stderr}`);
    assert.match(`${r.stderr}\n${r.stdout}`, /entropy-backstop:/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('G-29: Crypto.prototype and SubtleCrypto.prototype hooks are frozen', () => {
  const require = createRequire(import.meta.url);
  const crypto = require('node:crypto');
  const grv = Object.getOwnPropertyDescriptor(Crypto.prototype, 'getRandomValues');
  const gk = Object.getOwnPropertyDescriptor(SubtleCrypto.prototype, 'generateKey');
  assert.equal(grv?.configurable, false);
  assert.equal(grv?.writable, false);
  assert.equal(gk?.configurable, false);
  assert.equal(gk?.writable, false);
  assert.equal(typeof Crypto.prototype.getRandomValues, 'function');
  assert.equal(typeof SubtleCrypto.prototype.generateKey, 'function');
  assert.equal(crypto.webcrypto.getRandomValues, marker.wrappers['webcrypto.getRandomValues'] || marker.wrappers['Crypto.prototype.getRandomValues']);
});

test('G-29: package.json check:ph0 runs the backstop check', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.match(pkg.scripts['check:ph0'], /entropy-backstop-check[.]mjs/);
});
