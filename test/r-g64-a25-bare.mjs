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
