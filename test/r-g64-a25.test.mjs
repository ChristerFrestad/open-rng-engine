// A25-3 / A25-4 evidence-helper mode of tools/ci/entropy-backstop.mjs (HoQ addendum A25; CTO GO with changes 1-4).
// Each case runs a child node under the preload with ENTROPY_BACKSTOP_HELPER=a25 and checks its exit code:
// 86 = a wrapped crypto primitive was called with the token clear, 87 = gate or import rule broken, 88 = a walked
// call failed its identity/stack check. Hostile-src cases run on a temp copy of src/ and the preload, never on this tree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as P from '../verification/harness/run-plan.mjs';
import { ROOT, BACKSTOP, MARK, sha, child } from './fixtures/a25-child.mjs';
// The hostile-tree cases (temp copy of src/ and the preload) and the install-abort case need a parent without the
// preload: a preloaded parent (npm test) adds its own preload to every node child and refuses an unproven one. They
// live in test/r-g64-a25-bare.mjs, which tools/ci/j-calib-mutants.mjs runs bare (A25 baseline + A25-M*), never skipped.
test('A25: the bare-parent cases exist and are run by the j-calib gate (no case is skipped here)', () => {
  const b = readFileSync(join(ROOT, 'test/r-g64-a25-bare.mjs'), 'utf8');
  assert.ok((b.match(/^\s*test\(/gm) || []).length >= 3);
  assert.match(readFileSync(join(ROOT, 'tools/ci/j-calib-mutants.mjs'), 'utf8'), /const A25_TEST = \['test\/r-g64-a25\.test\.mjs', 'test\/r-g64-a25-bare\.mjs'\]/);
});

test('A25 constants: the plan k, F and mode equal the preload\'s; expectedWalks follows the rule', () => {
  // Read from the preload's text: importing it here would install it in this (possibly bare) process.
  const t = readFileSync(BACKSTOP, 'utf8');
  const c = (n) => { const m = new RegExp(`^export const ${n} = ('?)([\\w-]+)\\1;`, 'm').exec(t); assert.ok(m, n); return m[1] ? m[2] : Number(m[2]); };
  assert.deepEqual({ ...P.HELPER_PLAN }, { mode: c('HELPER_MODE_ID'), sample_k: c('HELPER_SAMPLE_K'), first_walk: c('HELPER_FIRST_WALK'), min_sampled_hits: c('HELPER_MIN_SAMPLED_HITS'), part_floor: c('HELPER_PART_FLOOR') });
  assert.equal(c('HELPER_PART_FLOOR'), c('HELPER_FIRST_WALK') + c('HELPER_MIN_SAMPLED_HITS') * 2 ** c('HELPER_SAMPLE_K'));
  // The fault-injection seam: the shipped install builds the gate only from the saved original, with no overrides.
  assert.deepEqual([...t.matchAll(/makeHelperGate\(([^)]*)\)/g)].map((m) => m[1]).filter((a) => !a.startsWith('fill,')), ['origFill']);
  assert.equal(P.buildPlan({ runId: 'a', M: { 'shuffle/adjacency-mod4/n-52': 2 }, N: 1 }).helper.sample_k, c('HELPER_SAMPLE_K'));
  const F = P.HELPER_PLAN.first_walk, s = 2 ** P.HELPER_PLAN.sample_k;
  const brute = (n) => { let w = 0; for (let i = 0; i < n; i++) if (i < F || i % s === 0) w++; return w; };
  for (const n of [0, 1, F - 1, F, F + 1, 10240, 10241, 20480, 20481, 123457]) assert.equal(P.expectedWalks(n), brute(n), `n=${n}`);
});

test('A25 mode: src runs through the gate; state, leak check and walk counts are reported; the first 10^4 calls are all walked', () => {
  const r = child(`const E = await import(SRC); for (let i = 0; i < 30000; i++) E.integer(0, 10); E.shuffle([1,2,3]); E.sample(10, 3); E.weightedPick([1, 2]);
process.stdout.write(JSON.stringify({ state: M().state, leak: M().assertNoGateLeak(E), counts: M().counts() }));`);
  assert.equal(r.status, 0, r.err);
  const o = JSON.parse(r.out);
  assert.deepEqual(o.state, { mode: 'a25', sample_k: P.HELPER_PLAN.sample_k, first_walk: P.HELPER_PLAN.first_walk, part_floor: P.HELPER_PLAN.part_floor, backstop_sha256: sha(readFileSync(BACKSTOP)) });
  assert.equal(o.leak, true);
  assert.ok(o.counts.gate_calls >= 30003, JSON.stringify(o.counts));
  assert.equal(o.counts.walks, P.expectedWalks(o.counts.gate_calls));
});

test('A25 mode adds no global: own keys of globalThis equal those under the normal preload (no handoff, CTO change 1)', () => {
  const code = `process.stdout.write(JSON.stringify(Reflect.ownKeys(globalThis).map(String)));`;
  const a = child(code), b = child(code, { mode: null });
  assert.equal(a.status, 0, a.err); assert.equal(b.status, 0, b.err);
  assert.deepEqual(JSON.parse(a.out), JSON.parse(b.out));
  const h = child(`process.stdout.write(String(Object.getOwnPropertySymbols(globalThis).some((s) => { const v = globalThis[s]; return typeof v === 'function' && /gate/i.test(v.name); })));`);
  assert.equal(h.out, 'false');
});

const TOKEN_CLEAR = {
  'import randomBytes': `(await import('node:crypto')).randomBytes(4);`,
  'import randomFillSync': `(await import('node:crypto')).randomFillSync(new Uint8Array(4));`,
  'default import': `(await import('crypto')).default.randomInt(3);`,
  'createRequire': `(await import('node:module')).createRequire(import.meta.url)('node:crypto').randomFillSync(new Uint8Array(4));`,
  'getBuiltinModule': `process.getBuiltinModule('node:crypto').randomFillSync(new Uint8Array(4));`,
  'webcrypto': `(await import('node:crypto')).webcrypto.getRandomValues(new Uint8Array(4));`,
  'globalThis.crypto': `globalThis.crypto.getRandomValues(new Uint8Array(4));`,
  'randomUUID': `globalThis.crypto.randomUUID();`,
};
for (const [name, call] of Object.entries(TOKEN_CLEAR)) {
  test(`A25-3: ${name} with the token clear exits 86, after src has used the gate`, () => {
    const r = child(`const E = await import(SRC); E.integer(0, 10);\n${call}\nprocess.stdout.write('ALIVE');`);
    assert.equal(r.status, 86, `${r.status} ${r.err}`); assert.equal(r.out, ''); assert.match(r.err, /A25/);
  });
}

const GATE_RULES = {
  'direct import of src/entropy/index.ts': [`await import(new URL('src/entropy/index.ts', ROOTURL).href);`, /only src\/index\.ts may/],
  'direct import of the gate URL': [`await import('rng-backstop-gate:node-crypto');`, /rng-backstop-gate/],
  'import of the preload after start': [`await import(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href);`, /not importable in helper mode/],
  // A vm script with the main-context loader imports with no parent URL; after the main entry has started that must
  // still be refused (kills A25-M11: the before-main allowance for parent undefined / startup cwd must end at main).
  'parentless vm import of the preload after main started': [`const vm = await import('node:vm'); await vm.runInThisContext(\`import(\${JSON.stringify(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href)})\`, { importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER }); process.stdout.write('ALIVE');`, /not importable in helper mode \(from undefined\)/],
  'resolve of the preload by import.meta.resolve': [`import.meta.resolve(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href); await import(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href);`, /not importable/],
};
for (const [name, [code, why]] of Object.entries(GATE_RULES)) {
  test(`A25-3: ${name} exits 87`, () => { const r = child(code); assert.equal(r.status, 87, `${r.status} ${r.err}`); assert.match(r.err, why); });
}

test('A25-3 gate: a prototype change is impossible in helper mode (TypedArray prototypes frozen at install)', () => {
  const r = child(`'use strict'; const E = await import(SRC); E.integer(0, 10);
const TAP = Object.getPrototypeOf(Uint8Array.prototype); let refused = 0;
for (const f of [() => Object.defineProperty(TAP, 'byteLength', { get() { return 0; } }), () => Object.setPrototypeOf(Uint8Array.prototype, null), () => Object.defineProperty(Uint8Array.prototype, 'byteLength', { value: 0 })]) { try { f(); } catch { refused++; } }
E.integer(0, 10); process.stdout.write(String(refused));`);
  assert.equal(r.status, 0, r.err); assert.equal(r.out, '3');
});


test('A25-4: a walked call (inside the first 10^4) with a changed stackTraceLimit exits 88', () => {
  const r = child(`const E = await import(SRC); for (let i = 0; i < 100; i++) E.integer(0, 2); Error.stackTraceLimit = 3; E.integer(0, 2); process.stdout.write('ALIVE');`);
  assert.equal(r.status, 88, `${r.status} ${r.err}`); assert.equal(r.out, '');
});
test('A25-4: after the first 10^4 a change is caught at the next sampled index (i mod 2^k = 0), not before', () => {
  const s = 2 ** P.HELPER_PLAN.sample_k, F = P.HELPER_PLAN.first_walk;
  const next = Math.ceil(F / s) * s;
  const r = child(`const E = await import(SRC); while (M().counts().gate_calls < ${F}) E.integer(0, 2);
const g0 = M().counts().gate_calls; Error.stackTraceLimit = 3;
while (M().counts().gate_calls < ${next}) E.integer(0, 2);
process.stdout.write('ALIVE ' + g0 + ' ' + M().counts().gate_calls + ' ' + M().counts().walks + '\\n'); E.integer(0, 2); process.stdout.write('AFTER');`);
  assert.equal(r.status, 88, `${r.status} ${r.err}`);
  const m = /^ALIVE (\d+) (\d+) (\d+)$/m.exec(r.out); assert.ok(m, r.out); assert.doesNotMatch(r.out, /AFTER/);
  assert.equal(Number(m[2]), next); assert.equal(Number(m[3]), P.expectedWalks(next));
});

test('A25: normal (non-helper) preload behaviour is unchanged: no helper state, src still runs', () => {
  const r = child(`const E = await import(SRC); E.integer(0, 10); process.stdout.write(JSON.stringify(globalThis[${MARK}].helper.state));`, { mode: null });
  assert.equal(r.status, 0, r.err); assert.equal(r.out, 'null');
});
