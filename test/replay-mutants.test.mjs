// Replay mutant kills (quality v5.5.6 M-100..M-110, M-117 (b)-(d); CPO-R99 O-69 R0). node --test, zero dependencies.
// Out of scope here (no producer exists before PH2): M-106 / M-107 / M-117 (a) producer halves, `labkit verify` (PH3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { blockPlan, blockPlanTotal } from '../src/entropy/blockPlan.ts';
import { checkRandomBytesReplay, validateReadsOutputSchema } from '../src/verify/index.ts';

function golden(n) {
  let out = '';
  for (let i = 0; i < n; i++) out += ((0xa5 + i) & 0xff).toString(16).padStart(2, '0');
  const reads = blockPlan(n).map((w) => ({ width: w, count: w }));
  return { kind: 'randomBytes', params: { n }, reads, bytesFetched: reads.reduce((a, r) => a + r.count, 0), output: out };
}
const G = new Map();
const gold = (n) => { if (!G.has(n)) G.set(n, golden(n)); return JSON.parse(JSON.stringify(G.get(n))); };
const fail = (e, code, msg) => { const r = checkRandomBytesReplay(e); assert.equal(r.ok, false, msg); if (code) assert.equal(r.code, code, `${msg}: ${r.detail}`); return r; };

// M-100: count != width on one entry (first/middle/last; +1/-1), bytesFetched left at 131,089 -> R5 first
test('M-100: single-entry count != width, n = 131,041 -> R5', () => {
  assert.deepEqual(blockPlan(131041), [65536, 65536, 17]);
  assert.equal(gold(131041).bytesFetched, 131089);
  for (const i of [0, 1, 2]) for (const d of [1, -1]) {
    const e = gold(131041); e.reads[i].count += d;
    if (e.reads[i].count > 65536 || e.reads[i].count < 17) { const r = fail(e, "R1", `entry ${i} ${d}`); assert.deepEqual(r.failures, ["R1"]); continue; } // 65537 and 16 are outside the schema range 17..65536 (cto-g1-spec L304-L305): FAIL at R1 before R5
    fail(e, 'R5', `entry ${i} ${d}`);
  }
});
// M-101: compensating pairs -> only R5
test('M-101: Σ right, entries wrong -> only R5', () => {
  for (const [n, reads] of [[65521, [[65536, 65535], [17, 18]]], [131041, [[65536, 65535], [65536, 65536], [17, 18]]], [131041, [[65536, 65536], [65536, 65520], [17, 33]]]]) {
    const e = gold(n); e.reads = reads.map(([width, count]) => ({ width, count }));
    const r = fail(e, 'R5', `n=${n}`); assert.deepEqual(r.failures, ['R5']);
  }
});
// M-102: zero entries -> R1 (schema minimum 17)
test('M-102: width = 0 / count = 0 entries -> R1', () => {
  const cases = [
    (e) => e.reads.push({ width: 0, count: 0 }), (e) => e.reads.unshift({ width: 0, count: 0 }), (e) => e.reads.splice(1, 0, { width: 0, count: 0 }),
    (e) => { e.reads[e.reads.length - 1] = { width: 17, count: 0 }; e.bytesFetched -= 17; }, (e) => { e.reads[e.reads.length - 1] = { width: 0, count: 17 }; },
  ];
  for (const [i, m] of cases.entries()) { const e = gold(65521); m(e); fail(e, 'R1', `case ${i}`); }
});
// M-103: grouped by width
test('M-103: reads grouped by width (count = number of reads) -> fail (R1/R4/R5)', () => {
  const c = [[131040, [[65536, 2]]], [131040, [[65536, 131072]]], [131041, [[65536, 2], [17, 1]]]];
  for (const [n, reads] of c) { const e = gold(n); e.reads = reads.map(([width, count]) => ({ width, count })); const r = fail(e, 'R1', `n=${n}`); assert.deepEqual(r.failures, ['R1']); } // G-1: exact first code
  const e = gold(131040); e.reads = [{ width: 65536, count: 2 }];
  assert.ok(validateReadsOutputSchema(e) !== null); // count 2 is below the schema minimum
});
// M-104: data-only counts with bytesFetched = n
test('M-104: data-only counts (count = width - 16) with bytesFetched = n -> R5 first, R7 in failures', () => {
  const e = gold(65521); e.reads = [{ width: 65536, count: 65520 }, { width: 17, count: 1 }]; e.bytesFetched = 65521;
  const r = fail(e, 'R1', 'M-104'); assert.deepEqual(r.failures, ['R1']); // G-1: count 1 < 17 is a schema reject
  const e2 = gold(65521); e2.reads = [{ width: 65536, count: 65520 }, { width: 17, count: 17 }]; e2.bytesFetched = 65537;
  const r2 = fail(e2, 'R5', 'M-104 in-range variant'); assert.ok(r2.failures.includes('R7'));
});
// M-105: bytesFetched wrong (overhead missing / one block only / ±1); "at least n" killed by every case
test('M-105: bytesFetched = n, n + 16, Σ ± 1 -> R6 with R7', () => {
  const cases = [];
  for (const n of [1, 65519, 65520, 65521, 131040]) cases.push([n, n]);
  for (const n of [65521, 131040]) cases.push([n, n + 16]);
  for (const n of [1, 65521]) for (const d of [1, -1]) cases.push([n, blockPlanTotal(n) + d]);
  for (const [n, bf] of cases) {
    const e = gold(n); e.bytesFetched = bf;
    const r = fail(e, 'R6', `n=${n} bf=${bf}`); assert.ok(r.failures.includes('R7'));
    assert.ok(bf >= n || bf === blockPlanTotal(n) - 1); // each case satisfies "at least n" yet fails
  }
});
// M-106 (replay half): every wrong overhead formula is killed by at least one listed n; correct evidence passes
test('M-106 (replay half): wrong overhead formulas are each killed at some n; correct goldens pass', () => {
  const NS = [1, 65519, 65520, 65521, 131040];
  for (const n of NS) assert.deepEqual(checkRandomBytesReplay(gold(n)), { ok: true }, `n=${n}`);
  const wrong = {
    floor: (n) => n + 16 * Math.floor(n / 65520), ceilPlus1: (n) => n + 16 * Math.ceil((n + 1) / 65520), floorPlus1: (n) => n + 16 * (Math.floor(n / 65520) + 1),
    max65536: (n) => n + 16 * Math.ceil(n / 65536), nOnly: (n) => n,
  };
  for (const [name, f] of Object.entries(wrong)) {
    const killing = NS.filter((n) => f(n) !== blockPlanTotal(n));
    assert.ok(killing.length > 0, `${name} not distinguished by the listed n`);
    for (const n of killing) { const e = gold(n); e.bytesFetched = f(n); assert.equal(checkRandomBytesReplay(e).ok, false, `${name} n=${n}`); }
  }
});
// M-107 / M-117 (b)-(d): forged n = 0 and invalid n -> R0 before R1
test('M-117 (b): forged n = 0, reads = [], output = "", bytesFetched = 0 -> R0 (replay) and schema reject', () => {
  const e = { kind: 'randomBytes', params: { n: 0 }, reads: [], bytesFetched: 0, output: '' };
  assert.deepEqual(fail(e, 'R0', 'n=0').failures, ['R0']);
  assert.notEqual(validateReadsOutputSchema(e), null);
});
test('M-117 (c): n = 0 with reads = [{17,17}], bytesFetched = 17 -> R0', () => {
  fail({ kind: 'randomBytes', params: { n: 0 }, reads: [{ width: 17, count: 17 }], bytesFetched: 17, output: '' }, 'R0', 'n=0 + read');
});
test('M-117 (d): n = -1, 0.5, "1", -0, NaN, 2^53, null, missing -> R0', () => {
  for (const n of [-1, 0.5, '1', -0, NaN, 2 ** 53, null, undefined]) {
    const e = gold(1); if (n === undefined) delete e.params.n; else e.params.n = n;
    fail(e, 'R0', `n=${String(n)}`);
  }
});
test('R0 mutant: a checker without R0 would accept nothing new: n = 1 golden passes, n = 0 is R0 not R1', () => {
  assert.deepEqual(checkRandomBytesReplay(gold(1)), { ok: true });
  const r = checkRandomBytesReplay({ kind: 'randomBytes', params: { n: 0 }, reads: [], bytesFetched: 0, output: '' });
  assert.equal(r.code, 'R0'); // an R0-less checker reports R1 (schema) here, so this kills the "R0 deleted" mutant
});
// M-108: reads entry schema -> R1
test('M-108: count/width missing, string, fractional, negative, -0, >= 2^53, extra property -> R1', () => {
  const bad = ['17', 16.5, -17, -0, 2 ** 53];
  for (const k of ['count', 'width']) {
    const e = gold(17); delete e.reads[0][k]; fail(e, 'R1', `${k} missing`);
    for (const v of bad) { const e2 = gold(17); e2.reads[0][k] = v; fail(e2, 'R1', `${k}=${String(v)}`); }
  }
  for (const x of ['bytes', 'offset']) { const e = gold(17); e.reads[0][x] = 'ab'; fail(e, 'R1', x); }
});
// M-109: order and length of reads
test('M-109: reordered, last dropped, extra appended -> R4 (with R7 where bytesFetched moves)', () => {
  let e = gold(65521); e.reads = [{ width: 17, count: 17 }, { width: 65536, count: 65536 }]; fail(e, 'R4', 'reordered');
  e = gold(131041); e.reads.pop(); e.bytesFetched = 131072; assert.ok(fail(e, 'R4', 'dropped').failures.includes('R7'));
  e = gold(65521); e.reads.push({ width: 17, count: 17 }); e.bytesFetched += 17; assert.ok(fail(e, 'R4', 'appended').failures.includes('R7'));
});
// M-110: check order / partial replay / never fetches
test('M-110: 1-entry n = 15 record [{30,30}], bytesFetched 30 -> R4', () => {
  const e = gold(15); e.reads = [{ width: 30, count: 30 }]; e.bytesFetched = 30; fail(e, 'R4', 'n=15');
});
test('M-110: replay never touches a CSPRNG (trap on every node:crypto / Web Crypto entry point)', () => {
  let touches = 0;
  const trapped = [], skipped = [];
  const trap = (obj, k, label) => { // own-property shadow; a non-configurable export is listed and covered by the static check below
    const own = Object.getOwnPropertyDescriptor(obj, k);
    const orig = obj[k];
    try { Object.defineProperty(obj, k, { configurable: true, writable: true, value: (...a) => { touches++; return orig.apply(obj, a); } }); }
    catch { skipped.push(label); return () => {}; }
    trapped.push(label);
    return () => { if (own) Object.defineProperty(obj, k, own); else delete obj[k]; };
  };
  const undo = [['randomFillSync'], ['randomBytes'], ['randomFill'], ['randomInt'], ['randomUUID'], ['getRandomValues']].map(([k]) => trap(crypto, k, `node:crypto.${k}`))
    .concat([trap(globalThis.crypto, 'getRandomValues', 'globalThis.crypto.getRandomValues'), trap(globalThis.crypto, 'randomUUID', 'globalThis.crypto.randomUUID')]);
  const mr = Math.random; Math.random = () => { touches++; return mr(); };
  try {
    for (const n of [1, 17, 65521, 131041]) {
      checkRandomBytesReplay(gold(n));
      const e = gold(n); e.reads[0].count -= 1; checkRandomBytesReplay(e); // a "repairing" replay would fetch here
      const e2 = gold(n); e2.bytesFetched += 1; checkRandomBytesReplay(e2);
    }
    checkRandomBytesReplay({ kind: 'randomBytes', params: { n: 0 }, reads: [], bytesFetched: 0, output: '' });
  } finally { undo.forEach((u) => u()); Math.random = mr; }
  assert.equal(touches, 0, `trapped ${trapped.join(', ')}; skipped ${skipped.join(', ')}`);
  assert.ok(trapped.includes('node:crypto.randomFillSync') && trapped.includes('globalThis.crypto.getRandomValues'));
  const r = trap(crypto, 'randomFillSync', 'self-check'); crypto.randomFillSync(new Uint8Array(1)); r(); assert.equal(touches, 1); // the trap counts
  // Static half: the verification module graph imports nothing that can fetch (only ../entropy/blockPlan.ts, which imports nothing).
  const src = (p) => readFileSync(new URL(`../src/${p}`, import.meta.url), 'utf8');
  for (const p of ['verify/replayRandomBytes.ts', 'verify/index.ts', 'entropy/blockPlan.ts']) {
    const t = src(p);
    assert.doesNotMatch(t, /from\s+['"]node:|require\(|\bcrypto\b\s*\.|getRandomValues|randomFill|randomBytes\(|Math\.random/, p);
  }
});
// E-5 (CPO-R104 G-3): minimum bytesFetched is 17 (n = 1: 1 + 16)
test('E-5: n = 1 golden has bytesFetched 17 and passes; 16 (or reads summing to 16) fails', () => {
  const e = gold(1); assert.equal(e.bytesFetched, 17); assert.deepEqual(e.reads, [{ width: 17, count: 17 }]); assert.deepEqual(checkRandomBytesReplay(e), { ok: true });
  const a = gold(1); a.bytesFetched = 16; const ra = fail(a, 'R6', 'bf 16'); assert.ok(ra.failures.includes('R7'));
  const b = gold(1); b.reads = [{ width: 16, count: 16 }]; b.bytesFetched = 16; fail(b, 'R1', 'width 16');
  const z = gold(1); z.reads = []; z.bytesFetched = 0; fail(z, 'R4', 'no reads');
  assert.equal(blockPlanTotal(1), 17);
});
