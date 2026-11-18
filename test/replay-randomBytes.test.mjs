// C-11 (CPO-R98) / R-93 replay invariant tests. node --test, zero dependencies; Node type stripping loads the .ts
// sources directly (no tsc available on the box; type-check pending, see SEAT-LOG C-11 entry).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blockPlan, blockCount, blockWidthAt, blockPlanTotal, MAX_DATA } from '../src/entropy/blockPlan.ts';
import { checkRandomBytesReplay, validateReadsOutputSchema } from '../src/verify/index.ts';

// Positive golden builder: output = the first n bytes of a 0xA5-seeded byte counter (R-56 pattern stub), lowercase hex.
function golden(n) {
  let out = '';
  for (let i = 0; i < n; i++) out += ((0xa5 + i) & 0xff).toString(16).padStart(2, '0');
  const reads = blockPlan(n).map((w) => ({ width: w, count: w }));
  return { kind: 'randomBytes', params: { n }, reads, bytesFetched: reads.reduce((a, r) => a + r.count, 0), output: out };
}
const clone = (o) => JSON.parse(JSON.stringify(o));
const GOLDEN_N = [1, 15, 16, 17, 65520, 65521, 65536, 65537, 131040, 131041];

// blockPlan vs the C-11 formula and the literal R-56 loop
test('blockPlan: formula n + 16*ceil(n/65520) equals Σ blockPlan(n), and helpers agree', () => {
  const ns = [...GOLDEN_N, 2, 100, 65519, 196560, 196561, 1_000_000];
  for (const n of ns) {
    const p = blockPlan(n);
    assert.equal(p.reduce((a, b) => a + b, 0), n + 16 * Math.ceil(n / 65520), `n=${n}`);
    assert.equal(blockPlanTotal(n), n + 16 * Math.ceil(n / 65520));
    assert.equal(blockCount(n), p.length);
    p.forEach((w, i) => { assert.equal(blockWidthAt(n, i), w); assert.ok(w >= 17 && w <= 65536); });
  }
  assert.deepEqual(blockPlan(1), [17]);
  assert.deepEqual(blockPlan(65520), [65536]);
  assert.deepEqual(blockPlan(65521), [65536, 17]);
  assert.equal(MAX_DATA, 65520);
});
test('blockPlan: n = 0, negative, non-integer, unsafe -> RANGE_INVALID', () => {
  for (const n of [0, -1, 1.5, NaN, Infinity, 2 ** 53, '1']) assert.throws(() => blockPlan(n), /RANGE_INVALID/);
});

for (const n of GOLDEN_N) {
  test(`positive golden n=${n} -> ok`, () => assert.deepEqual(checkRandomBytesReplay(golden(n)), { ok: true }));
}

const expectFail = (e, code, alsoIn = []) => {
  const r = checkRandomBytesReplay(e);
  assert.equal(r.ok, false);
  assert.equal(r.code, code, r.detail);
  for (const c of alsoIn) assert.ok(r.failures.includes(c), `${c} in ${r.failures}`);
};
const neg = (name, mutate, code, alsoIn) => test(`negative ${code}: ${name}`, () => {
  const e = clone(golden(name.includes('multi-block') ? 65537 : 17));
  mutate(e);
  expectFail(e, code, alsoIn);
});

// R1 schema
test('negative R1: non-object evidence', () => { for (const v of [null, [], 'x', 7]) expectFail(v, 'R1'); });
neg('missing output', (e) => { delete e.output; }, 'R1');
neg('output not a string', (e) => { e.output = 7; }, 'R1');
neg('missing reads', (e) => { delete e.reads; }, 'R1');
neg('missing bytesFetched', (e) => { delete e.bytesFetched; }, 'R1');
neg('bytesFetched not integer', (e) => { e.bytesFetched = 33.5; }, 'R1');
neg('params.n missing', (e) => { e.params = {}; }, 'R0');
neg('params.n = 0 (PLAN L605)', (e) => { e.params.n = 0; e.output = ''; e.reads = []; e.bytesFetched = 0; }, 'R0');
neg('params.n not integer', (e) => { e.params.n = 1.5; }, 'R0');
neg('byte payload inside a read entry (additionalProperties)', (e) => { e.reads[0].bytes = 'ab'; }, 'R1');
neg('read entry missing count', (e) => { delete e.reads[0].count; }, 'R1');
neg('read width below 17', (e) => { e.reads[0].width = 16; }, 'R1');
neg('read count above 65536', (e) => { e.reads[0].count = 65537; }, 'R1');
neg('read entry is a hex string', (e) => { e.reads[0] = 'a5a6a7a8'; }, 'R1');
neg('kind is a mapping primitive', (e) => { e.kind = 'randomInt'; }, 'R1');
test('negative R1: output field on a mapping primitive (schema else-branch)', () => {
  const m = { kind: 'shuffle', params: {}, reads: ['a5a6a7a8'], bytesFetched: 4, output: 'ab' };
  assert.match(validateReadsOutputSchema(m), /output present on a mapping primitive/);
  delete m.output;
  assert.equal(validateReadsOutputSchema(m), null);
});

// R2 len(output) == n
neg('output one byte short', (e) => { e.output = e.output.slice(0, -2); }, 'R2');
neg('output one byte long', (e) => { e.output += 'ab'; }, 'R2');
neg('odd length (one hex char short)', (e) => { e.output = e.output.slice(0, -1); }, 'R2', ['R3']);
neg('0x prefix', (e) => { e.output = '0x' + e.output; }, 'R2', ['R3']);
neg('separator', (e) => { e.output = e.output.slice(0, 2) + ':' + e.output.slice(2); }, 'R2', ['R3']);

// R3 lowercase even-length hex (same length as expected, so R2 passes)
neg('uppercase output', (e) => { e.output = e.output.toUpperCase(); }, 'R3');
neg('one uppercase nibble', (e) => { e.output = 'A' + e.output.slice(1); }, 'R3');
neg('0x prefix replacing first byte', (e) => { e.output = '0x' + e.output.slice(2); }, 'R3');
neg('separator replacing a nibble pair', (e) => { e.output = e.output.slice(0, 2) + '::' + e.output.slice(4); }, 'R3');
neg('non-hex letter', (e) => { e.output = 'g' + e.output.slice(1); }, 'R3');

// R4 reads.length and widths vs blockPlan(n)
neg('multi-block: a missing read', (e) => { e.reads.pop(); e.bytesFetched = e.reads.reduce((a, r) => a + r.count, 0); }, 'R4');
neg('an extra read', (e) => { e.reads.push({ width: 17, count: 17 }); e.bytesFetched += 17; }, 'R4');
neg('width off by one (+1, count follows)', (e) => { e.reads[0].width += 1; e.reads[0].count += 1; e.bytesFetched += 1; }, 'R4');
neg('multi-block: width off by one (-1) in first block', (e) => { e.reads[0].width -= 1; e.reads[0].count -= 1; e.bytesFetched -= 1; }, 'R4');
neg('multi-block: blocks swapped', (e) => { e.reads.reverse(); }, 'R4');

// R5 count === width
neg('count != width (short count)', (e) => { e.reads[0].count -= 1; e.bytesFetched -= 1; }, 'R5');
neg('multi-block: count != width in last block', (e) => { e.reads[1].count += 1; e.bytesFetched += 1; }, 'R5');

// R6 Σcount === bytesFetched
neg('Σcount != bytesFetched (+1)', (e) => { e.bytesFetched += 1; }, 'R6', ['R7']);
neg('bytesFetched = n (fingerprint omitted)', (e) => { e.bytesFetched = e.params.n; }, 'R6', ['R7']);
neg('multi-block: bytesFetched counts one fingerprint only', (e) => { e.bytesFetched = e.params.n + 16; }, 'R6', ['R7']);

// R7 bytesFetched === n + 16*ceil(n/65520), reported alongside R6 (see checker note)
test('negative R7: bytesFetched off the formula is always in failures', () => {
  for (const d of [-16, -1, 1, 16]) {
    const e = golden(65537); e.bytesFetched += d;
    const r = checkRandomBytesReplay(e);
    assert.equal(r.ok, false); assert.ok(r.failures.includes('R7'), String(r.failures));
  }
});
test('R5 alone (count and width both 17..65536, Σ unchanged) still fails', () => {
  const e = golden(65537); e.reads[0].count -= 1; e.reads[1].count += 1; // Σcount unchanged
  const r = checkRandomBytesReplay(e);
  assert.equal(r.code, 'R5'); assert.deepEqual(r.failures, ['R5']);
});
