// R-DT-MC framework and the duplicates exact sampler (CTO batch K2; HoQ R-DT-MC / R-DT-SAMPLER). No MC run here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as S from '../verification/statistic/wave1-statistic.mjs';
import * as MCm from '../verification/mc/dt-mc.mjs';
import { ivFor } from '../verification/labkit/aes-ctr-ref.mjs';

const TEST_KEY = '00'.repeat(31) + '01'; // test-only key; real key is pre-registered later

test('p_MC = (1 + #>=)/(B + 1) with B + 1 = 1,004,800; ties count as >=; flag iff #>= <= 62 (62/63 boundary)', () => {
  assert.equal(MCm.MC.B_PLUS_1, 1004800); assert.equal(MCm.MC.B, MCm.MC.B_PLUS_1 - 1);
  assert.equal(MCm.pMC(0), 1 / 1004800); assert.equal(MCm.pMC(62), 63 / 1004800); assert.equal(MCm.pMC(1004799), 1);
  assert.equal(MCm.mcFlag(62), true); assert.equal(MCm.mcFlag(63), false); assert.equal(MCm.mcFlag(0), true);
  assert.ok(MCm.pMC(62) <= 6.369e-5 && MCm.pMC(63) > 6.369e-5);
  assert.equal(MCm.exceeds(5.25, 5.25), true); assert.equal(MCm.exceeds(5.2499, 5.25), false); assert.equal(MCm.exceeds(6, 5.25), true);
});

test('no curtailment: the block plan covers exactly B = 1,004,799 replications in 1,005 blocks (last 799)', () => {
  assert.equal(MCm.nBlocks(), 1005); let t = 0; for (let b = 0; b < MCm.nBlocks(); b++) t += MCm.blockReps(b);
  assert.equal(t, 1004799); assert.equal(MCm.blockReps(1004), 799); assert.equal(MCm.blockReps(1005), 0);
});

test('IV domains: the MC domain field separates every MC block IV from every calibration IV; blocks never share a stream', () => {
  const calWord0 = new Set(); for (let st = 1; st <= 26; st++) calWord0.add(ivFor(st, 0).readUInt32BE(0));
  const seen = new Set();
  for (let e = 0; e < 26; e++) for (let b = 0; b < MCm.nBlocks(); b++) {
    const w = MCm.ivWords(e, b); assert.equal(w[0], MCm.MC.DOMAIN); assert.ok(!calWord0.has(w[0]));
    assert.equal(w[2], 0); assert.equal(w[3], 0); const key = `${w[0]}:${w[1]}`; assert.ok(!seen.has(key), key); seen.add(key);
  }
  assert.ok((MCm.MC.DOMAIN & 0x40000000) !== 0);
  const a = MCm.mcStream(TEST_KEY, 3, 7), b = MCm.mcStream(TEST_KEY, 3, 8), c = MCm.mcStream(TEST_KEY, 4, 7);
  const w = (s) => [s.u32(), s.u32(), s.u32()].join(','); const [x, y, z] = [w(a), w(b), w(c)];
  assert.notEqual(x, y); assert.notEqual(x, z);
});

// Small law for the sampler KAT: 4 cells 1/10, 2/10, 3/10, 4/10 (den 10 scaled by 2^s inside the sampler).
const small = { cellNum: [1n, 2n, 3n, 4n], den: 10n };
test('exact sampler KAT: marginal histogram matches the exact law (Pearson p > 1e-4), and the exact tie path decides by the full bits', () => {
  const s = MCm.mcStream(TEST_KEY, 0, 0); const smp = MCm.exactSampler(small); const N = 200000; const c = [0, 0, 0, 0];
  for (let i = 0; i < N; i++) c[smp.draw(() => s.u32())] += 1;
  let x2 = 0; [0.1, 0.2, 0.3, 0.4].forEach((p, j) => { x2 += (c[j] - N * p) ** 2 / (N * p); });
  assert.ok(S.chi2sf(x2, 3) > 1e-4, `x2 ${x2} counts ${c}`);
  // Scripted words: den 10 -> L = 64 bits exactly (s = 60); boundary 1/10 at 0x1999999999999999.9.. -> top(cum0) = 2^60.
  // L - 64 = 0 here, so use a law whose den needs more than 64 bits to reach the tie path.
  const big = { cellNum: [(1n << 70n) + 1n, (1n << 70n) - 1n], den: 1n << 71n }; // L = 72, sh = 8
  const sb = MCm.exactSampler(big); const top = ((1n << 70n) + 1n) >> 8n;
  const script = (words) => { let i = 0; return () => { if (i >= words.length) throw new Error('drew past script'); return words[i++]; }; };
  const hi = Number(top >> 32n), lo = Number(top & 0xffffffffn);
  assert.equal(sb.draw(script([hi, lo, 0x00000000])), 0, 'rest 0 < low bits 1 -> cell 0');
  assert.equal(sb.draw(script([hi, lo, 0x01000000])), 1, 'rest 1 >= low bits 1 -> cell 1');
  assert.equal(sb.stats().slow, 2);
  assert.equal(sb.draw(script([0xffffffff, 0xffffffff, 0xff000000, 0, 0, 0])), 0, 'X >= den rejected, redrawn');
});

const E12 = S.ENTRIES[12];
function testSetup() {
  const M = 300; const lumped = S.lumpExact(S.lawExact(E12), M);
  const man = { ...MCm.nullManifest({ entryIndex: 12, e: E12, M, lumped, keyId: 'test-only', keyHex: TEST_KEY }), B: 10, block_size: 4, n_blocks: 3 };
  return { M, lumped, man };
}
test('null manifest: no observed X² field; pins domain, IV scheme, B, block size, cell order and code digests', () => {
  const { man } = testSetup(); const full = MCm.nullManifest({ entryIndex: 12, e: E12, M: 300, lumped: S.lumpExact(S.lawExact(E12), 300), keyId: 't', keyHex: TEST_KEY });
  assert.ok(!JSON.stringify(full).toLowerCase().includes('x2')); assert.equal(full.B, 1004799); assert.equal(full.n_blocks, 1005);
  assert.deepEqual(Object.keys(full.digests).sort(), ['adapter', 'sampler', 'statistic']); assert.equal(man.domain, MCm.MC.DOMAIN);
  assert.throws(() => MCm.nullManifest({ entryIndex: 0, e: S.ENTRIES[0], M: 10, lumped: { cellNum: [1n], den: 1n }, keyId: 't', keyHex: TEST_KEY }), /duplicates/);
});

test('resume: a recomputed block is digest-identical; runEntry assembles #>= over all blocks and refuses drifted inputs', () => {
  const { lumped, man } = testSetup(); const d = mkdtempSync(join(tmpdir(), 'dtmc-'));
  try {
    const x2obs = 20;
    assert.equal(MCm.runEntry(man, lumped, TEST_KEY, x2obs, d, { maxBlocks: 2 }), null); // interrupted after 2 blocks
    const b1 = readFileSync(join(d, 'block-0001.json'), 'utf8'); unlinkSync(join(d, 'block-0001.json'));
    const r = MCm.runEntry(man, lumped, TEST_KEY, x2obs, d);
    assert.equal(readFileSync(join(d, 'block-0001.json'), 'utf8'), b1);
    const blocks = [0, 1, 2].map((b) => JSON.parse(readFileSync(join(d, `block-000${b}.json`), 'utf8')));
    assert.deepEqual(blocks.map((x) => x.reps), [4, 4, 2]); assert.notEqual(blocks[0].x2_sha256, blocks[1].x2_sha256);
    assert.equal(r.reps, 10); assert.equal(r.ge, blocks.reduce((a, x) => a + x.ge, 0)); assert.equal(r.p_mc, (1 + r.ge) / 11);
    // Replay block 0 by hand: same draws, same X², same #>=.
    const again = MCm.runBlock(man, lumped, TEST_KEY, 0, x2obs); assert.equal(again.x2_sha256, blocks[0].x2_sha256); assert.equal(again.ge, blocks[0].ge);
    // Ties: x2obs equal to a simulated X² counts it.
    const tieBlock = MCm.runBlock(man, lumped, TEST_KEY, 0, 0); assert.equal(tieBlock.ge, 4);
    assert.throws(() => MCm.runEntry({ ...man, cell_order_sha256: '0'.repeat(64) }, lumped, TEST_KEY, x2obs, d), /cell order/);
    assert.throws(() => MCm.runEntry(man, lumped, '00'.repeat(32), x2obs, d), /key/);
    writeFileSync(join(d, 'block-0002.json'), JSON.stringify({ ...blocks[2], manifest_sha256: 'x' }));
    assert.equal(MCm.runEntry(man, lumped, TEST_KEY, x2obs, d).ge, r.ge, 'a block from another manifest is recomputed');
  } finally { rmSync(d, { recursive: true, force: true }); }
});
