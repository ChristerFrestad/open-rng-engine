// A25-3 bare-parent cases for tools/ci/entropy-backstop.mjs helper mode. Not a *.test.mjs: npm test runs under the
// preload, which re-preloads every node child and refuses one that never proves the preload, so these cases cannot run
// there. tools/ci/j-calib-mutants.mjs runs this file with no NODE_OPTIONS (A25 baseline must be green, 0 skipped,
// and the A25-M* mutants run against it); test/r-g64-a25.test.mjs checks that wiring.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { child, withHostile, fillBody, isBare } from './fixtures/a25-child.mjs';

test('A25 bare cases: this process has no preload (run by tools/ci/j-calib-mutants.mjs)', () => { assert.ok(isBare(), 'run this file from a parent without the preload'); });
test('A25-3: an unknown helper mode value exits 87', () => { const r = child('1;', { mode: 'a24' }); assert.equal(r.status, 87, r.err); });

const BAD_ARGS = {
  'an offset argument': `  randomFillSync(target, 0);`,
  'offset with a valueOf that calls crypto (CTO change 2)': `  randomFillSync(target, { valueOf() { process.stderr.write('VALUEOF-RAN'); return (globalThis as any).crypto.getRandomValues(new Uint8Array(1))[0] & 0; } } as any);`,
  'offset and size': `  randomFillSync(target, 0, target.length);`,
  'a DataView': `  randomFillSync(new DataView(target.buffer));`,
  'an ArrayBuffer': `  randomFillSync(target.buffer);`,
  'a Buffer': `  randomFillSync(Buffer.from(target.buffer));`,
  'a Uint8Array subclass': `  class U extends Uint8Array {} randomFillSync(new U(target.length));`,
  'a Uint32Array': `  randomFillSync(new Uint32Array(1));`,
  'an own byteLength on the target': `  Object.defineProperty(target, 'byteLength', { value: 0 }); randomFillSync(target);`,
  'a plain object': `  randomFillSync({ length: 4 } as any);`,
};
for (const [name, body] of Object.entries(BAD_ARGS)) {
  test(`A25-3 gate refuses ${name} before setting the token: exit 87`, () => {
    const r = withHostile(fillBody(body), `const E = await import(SRC); E.integer(0, 10); process.stdout.write('ALIVE');`);
    assert.equal(r.status, 87, `${r.status} ${r.err}`); assert.doesNotMatch(r.err, /VALUEOF-RAN/); assert.equal(r.out, '');
  });
}

test('A25-3 / CTO change 3: src/index.ts re-exporting the gate fails the leak check: exit 87', () => {
  const r = withHostile({ 'src/index.ts': (t) => `${t}\nexport { randomFillSync as __leak } from './entropy/index.ts';\n` },
    `const E = await import(SRC); M().assertNoGateLeak(E); process.stdout.write('ALIVE');`);
  assert.equal(r.status, 87, `${r.status} ${r.err}`); assert.match(r.err, /leak|gate/i); assert.equal(r.out, '');
});

// CTO answer (a): the token is cleared in finally when the fill throws. The real randomFillSync cannot be made to
// throw on a valid target, so the gate is built through its factory (makeHelperGate) with a throwing fill, in normal
// mode where the preload may be imported. The installed gate's token is a separate closure and is not reachable.
test('A25-3: the gate clears its token in finally when the fill throws (makeHelperGate seam, normal mode)', () => {
  const r = child(`const B = await import(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href);
let n = 0; const H = B.makeHelperGate((t) => { n++; if (n === 1) throw new Error('FILL-THREW'); t[0] = 7; }, { walk: () => {} });
let threw = false; try { H.gate(new Uint8Array(4)); } catch (e) { threw = /FILL-THREW/.test(e.message); }
const tokenAfter = H.tokenSet(); const u = H.gate(new Uint8Array(4));
process.stdout.write(JSON.stringify({ threw, tokenAfter, second: u[0], counts: H.counts() }));`, { mode: null });
  assert.equal(r.status, 0, `${r.status} ${r.err}`);
  assert.deepEqual(JSON.parse(r.out), { threw: true, tokenAfter: false, second: 7, counts: { gate_calls: 2, walks: 2 } });
});

// CTO 15:2x: each instance has its own token, proven rather than claimed. In normal mode, while instance A's token is
// set (inside its fill): instance B's token is clear and B's gate works; a direct crypto.randomBytes call is not
// satisfied by A's token (the wrapped primitive still runs its own checks and refuses this caller); then re-entering
// A's gate exits 86. Kills A25-M22 (one token shared by every instance). In helper mode a wrapped primitive exits 86
// whatever any token says (wrapFn), and no instance but the installed one can exist there (resolve hook, exit 87).
test('A25-3: a factory-built instance has its own token; it neither satisfies a wrapped primitive nor blocks another instance (exit 86 on re-entry)', () => {
  const r = child(`const B = await import(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href);
const C = await import('node:crypto');
const seen = {};
const H2 = B.makeHelperGate((t) => { t[0] = 9; }, { walk: () => {} });
let H1;
H1 = B.makeHelperGate((t) => {
  seen.ownSet = H1.tokenSet(); seen.otherSet = H2.tokenSet();
  seen.other = H2.gate(new Uint8Array(2))[0];
  try { C.randomBytes(4); seen.rb = 'PASSED'; } catch (e) { seen.rb = 'REFUSED: ' + e.message; }
  process.stdout.write(JSON.stringify(seen));
  H1.gate(new Uint8Array(1));
  process.stdout.write('NOT-REACHED');
}, { walk: () => {} });
H1.gate(new Uint8Array(4));
process.stdout.write('NOT-REACHED');`, { mode: null });
  assert.equal(r.status, 86, `${r.status} ${r.err}`);
  assert.match(r.err, /gate re-entered while the token is set \(exit 86\)/);
  const seen = JSON.parse(r.out);
  assert.equal(seen.ownSet, true); assert.equal(seen.otherSet, false); assert.equal(seen.other, 9);
  assert.match(seen.rb, /^REFUSED: entropy-backstop: randomBytes/);
});

// A25-M11 retirement (HoQ/CTO 22:22 rulings): no coverage lost. Each refusal on the parentless-code paths is pinned to its
// exact exit code here, in the bare-parent run (child in helper mode under the real preload + lockdown), and each has a
// kill mutant in tools/ci/a25-2-wiring-mutants.mjs (M50 eval, M51 new Function, M52 getBuiltinModule('vm')).
const M11_REPLACEMENTS = {
  'eval (M50)': [`const E = await import(SRC); E.integer(0, 10); eval('1'); process.stdout.write('ALIVE');`, 91, /eval called after boot/],
  'new Function (M51)': [`const E = await import(SRC); E.integer(0, 10); new Function('return 1')(); process.stdout.write('ALIVE');`, 91, /Function called after boot/],
  "process.getBuiltinModule('vm') (M52)": [`const E = await import(SRC); E.integer(0, 10); process.getBuiltinModule('vm'); process.stdout.write('ALIVE');`, 92, /getBuiltinModule\('vm'\)/],
};
for (const [name, [code, want, why]] of Object.entries(M11_REPLACEMENTS)) {
  test(`A25-M11 replacement: ${name} exits ${want}`, () => {
    const r = child(code);
    assert.equal(r.status, want, `${r.status} ${r.err}`); assert.equal(r.out, ''); assert.match(r.err, why);
  });
}
