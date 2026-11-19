import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidBlockPlanN as isValidNew,
  blockPlan as blockPlanNew,
  blockCount as blockCountNew,
  blockWidthAt as blockWidthAtNew,
  blockPlanTotal as blockPlanTotalNew,
} from '../src/entropy/blockPlan.ts';
import {
  checkRandomBytesReplay as replayNew,
  validateReadsOutputSchema as schemaNew,
} from '../src/verify/index.ts';
import {
  isValidBlockPlanN as isValidOld,
  blockPlan as blockPlanOld,
  blockCount as blockCountOld,
  blockWidthAt as blockWidthAtOld,
  blockPlanTotal as blockPlanTotalOld,
  checkRandomBytesReplay as replayOld,
  validateReadsOutputSchema as schemaOld,
} from './fixtures/pre-g43-predicates.mjs';

function catcher(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    return { ok: false, name: e && e.name, message: e && e.message };
  }
}

function goldenFrom(blockPlan, n) {
  let out = '';
  for (let i = 0; i < n; i++) out += ((0xa5 + i) & 0xff).toString(16).padStart(2, '0');
  const reads = blockPlan(n).map((w) => ({ width: w, count: w }));
  return { kind: 'randomBytes', params: { n }, reads, bytesFetched: reads.reduce((a, r) => a + r.count, 0), output: out };
}

const NS = [0, 1, -1, 1.5, NaN, Infinity, 2 ** 53, '1', null, undefined, {}, []];
const GOLDEN_N = [1, 15, 16, 17, 65520, 65521, 65536, 65537, 131040, 131041];

test('G-43: isValidBlockPlanN is behaviour-identical to 0a94759f over the fixed corpus', () => {
  for (const n of NS) {
    assert.equal(isValidNew(n), isValidOld(n), `isValidBlockPlanN(${String(n)})`);
  }
});

test('G-43: blockPlan/helpers throw the same type and message, and return the same values', () => {
  for (const n of NS) {
    assert.deepEqual(catcher(() => blockPlanNew(n)), catcher(() => blockPlanOld(n)), `blockPlan(${String(n)})`);
    assert.deepEqual(catcher(() => blockCountNew(n)), catcher(() => blockCountOld(n)), `blockCount(${String(n)})`);
    assert.deepEqual(catcher(() => blockPlanTotalNew(n)), catcher(() => blockPlanTotalOld(n)), `blockPlanTotal(${String(n)})`);
    assert.deepEqual(catcher(() => blockWidthAtNew(n, 0)), catcher(() => blockWidthAtOld(n, 0)), `blockWidthAt(${String(n)}, 0)`);
  }
  for (const n of GOLDEN_N) {
    const p = blockPlanNew(n);
    assert.deepEqual(p, blockPlanOld(n), `golden blockPlan(${n})`);
    assert.equal(blockCountNew(n), blockCountOld(n));
    assert.equal(blockPlanTotalNew(n), blockPlanTotalOld(n));
    p.forEach((_, i) => assert.equal(blockWidthAtNew(n, i), blockWidthAtOld(n, i)));
    assert.deepEqual(catcher(() => blockWidthAtNew(n, -1)), catcher(() => blockWidthAtOld(n, -1)));
    assert.deepEqual(catcher(() => blockWidthAtNew(n, p.length)), catcher(() => blockWidthAtOld(n, p.length)));
  }
});

function replayShapes() {
  const g = (n) => goldenFrom(blockPlanOld, n);
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const shapes = [];
  for (const n of NS) shapes.push(n);
  for (const n of GOLDEN_N) shapes.push(g(n));
  shapes.push(null, [], 'x', 7, {}, { kind: 'randomBytes' });
  const missingOut = clone(g(17)); delete missingOut.output; shapes.push(missingOut);
  const outNotStr = clone(g(17)); outNotStr.output = 7; shapes.push(outNotStr);
  const missingReads = clone(g(17)); delete missingReads.reads; shapes.push(missingReads);
  const missingBf = clone(g(17)); delete missingBf.bytesFetched; shapes.push(missingBf);
  const bfFrac = clone(g(17)); bfFrac.bytesFetched = 33.5; shapes.push(bfFrac);
  const nMissing = clone(g(17)); nMissing.params = {}; shapes.push(nMissing);
  const n0 = clone(g(17)); n0.params.n = 0; n0.output = ''; n0.reads = []; n0.bytesFetched = 0; shapes.push(n0);
  const nFrac = clone(g(17)); nFrac.params.n = 1.5; shapes.push(nFrac);
  const nStr = clone(g(17)); nStr.params.n = '1'; shapes.push(nStr);
  const nNeg = clone(g(17)); nNeg.params.n = -1; shapes.push(nNeg);
  const nNan = clone(g(17)); nNan.params.n = NaN; shapes.push(nNan);
  const nInf = clone(g(17)); nInf.params.n = Infinity; shapes.push(nInf);
  const nUnsafe = clone(g(17)); nUnsafe.params.n = 2 ** 53; shapes.push(nUnsafe);
  const extraProp = clone(g(17)); extraProp.reads[0].bytes = 'ab'; shapes.push(extraProp);
  const missCount = clone(g(17)); delete missCount.reads[0].count; shapes.push(missCount);
  const widthLo = clone(g(17)); widthLo.reads[0].width = 16; shapes.push(widthLo);
  const countHi = clone(g(17)); countHi.reads[0].count = 65537; shapes.push(countHi);
  const readHex = clone(g(17)); readHex.reads[0] = 'a5a6a7a8'; shapes.push(readHex);
  const mapping = clone(g(17)); mapping.kind = 'randomInt'; shapes.push(mapping);
  const mappingOut = { kind: 'shuffle', params: {}, reads: ['a5a6a7a8'], bytesFetched: 4, output: 'ab' };
  shapes.push(mappingOut);
  const mappingOk = { kind: 'shuffle', params: {}, reads: ['a5a6a7a8'], bytesFetched: 4 };
  shapes.push(mappingOk);
  const shortOut = clone(g(17)); shortOut.output = shortOut.output.slice(0, -2); shapes.push(shortOut);
  const longOut = clone(g(17)); longOut.output += 'ab'; shapes.push(longOut);
  const oddOut = clone(g(17)); oddOut.output = oddOut.output.slice(0, -1); shapes.push(oddOut);
  const upper = clone(g(17)); upper.output = upper.output.toUpperCase(); shapes.push(upper);
  const missingRead = clone(g(65537)); missingRead.reads.pop(); missingRead.bytesFetched = missingRead.reads.reduce((a, r) => a + r.count, 0); shapes.push(missingRead);
  const extraRead = clone(g(17)); extraRead.reads.push({ width: 17, count: 17 }); extraRead.bytesFetched += 17; shapes.push(extraRead);
  const widthOff = clone(g(17)); widthOff.reads[0].width += 1; widthOff.reads[0].count += 1; widthOff.bytesFetched += 1; shapes.push(widthOff);
  const countShort = clone(g(17)); countShort.reads[0].count -= 1; countShort.bytesFetched -= 1; shapes.push(countShort);
  const bfPlus = clone(g(17)); bfPlus.bytesFetched += 1; shapes.push(bfPlus);
  const bfN = clone(g(17)); bfN.bytesFetched = bfN.params.n; shapes.push(bfN);
  const r5swap = clone(g(65537)); r5swap.reads[0].count -= 1; r5swap.reads[1].count += 1; shapes.push(r5swap);
  return shapes;
}

test('G-43: checkRandomBytesReplay and validateReadsOutputSchema are behaviour-identical over replay dict shapes', () => {
  const shapes = replayShapes();
  for (let i = 0; i < shapes.length; i++) {
    const e = shapes[i];
    assert.deepEqual(replayNew(e), replayOld(e), `checkRandomBytesReplay shape ${i}`);
    assert.equal(schemaNew(e), schemaOld(e), `validateReadsOutputSchema shape ${i}`);
  }
});
