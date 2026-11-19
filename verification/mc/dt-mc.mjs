// R-DT-MC Monte-Carlo p framework (CPO-R116, HoQ R-DT-MC / R-DT-SAMPLER) and the EXACT per-observation null
// sampler for the duplicates entries (12..23). NO run and NO real key here: pre-registration comes after HoQ rules.
// - p_MC = (1 + #>=) / (B + 1), B + 1 = 1,004,800, ties counted as >=; flag iff #>= <= 62. No curtailment: all
//   1,005 blocks (1,004 x 1,000 + 799) always run.
// - Sampler: exact categorical draw from THE module's exact lumped law using labkit words only. X is uniform on
//   [0, 2^L) (L = max(bitlen(den), 64) after scaling every boundary by 2^s), read 64 bits first; the cell is found
//   by binary search on the boundaries' top 64 bits; if X's prefix equals a boundary prefix the remaining L - 64
//   bits are drawn and compared exactly in BigInt; X >= den·2^s is rejected and redrawn. No floats decide anything.
// - Streams: labkit AES-256-CTR with IV = BE32(MC_DOMAIN) || BE32(entry << 11 | block) || 0^64. MC_DOMAIN has bit
//   30 set; calibration IVs are BE32(stream 1..26) || BE32(rep) || 0^64, so the domain field alone separates them
//   (the tested stream is the engine's own output, not this generator). 64-bit counter room per block.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import * as S from '../statistic/wave1-statistic.mjs';
import { RefStream } from '../labkit/aes-ctr-ref.mjs';

export const MC = Object.freeze({ B_PLUS_1: 1004800, B: 1004799, BLOCK: 1000, FLAG_MAX_GE: 62, DOMAIN: 0x4d430001 });
export const nBlocks = (B = MC.B, size = MC.BLOCK) => Math.ceil(B / size);
export const blockReps = (b, B = MC.B, size = MC.BLOCK) => Math.max(0, Math.min(size, B - b * size));
export const ivWords = (entry, block) => [MC.DOMAIN, ((entry << 11) | block) >>> 0, 0, 0];
export function mcStream(keyHex, entry, block) {
  if (!(entry >= 0 && entry < 2 ** 21 && block >= 0 && block < 2048)) throw new Error('mcStream: entry/block out of range');
  return new RefStream(MC.DOMAIN, ((entry << 11) | block) >>> 0, keyHex);
}
export const pMC = (ge) => (1 + ge) / MC.B_PLUS_1;
export const mcFlag = (ge) => ge <= MC.FLAG_MAX_GE;
export const exceeds = (x2sim, x2obs) => x2sim >= x2obs; // ties count as >=

const bitlen = (n) => n.toString(2).length;
export function exactSampler(lumped) {
  const L0 = bitlen(lumped.den); const s = Math.max(0, 64 - L0); const L = L0 + s; const sh = BigInt(L - 64);
  const cum = []; { let c = 0n; for (const x of lumped.cellNum) { c += x << BigInt(s); cum.push(c); } } // cum[k-1] = den·2^s
  const hi = Uint32Array.from(cum, (c) => Number((c >> sh) >> 32n)), lo = Uint32Array.from(cum, (c) => Number((c >> sh) & 0xffffffffn));
  const k = cum.length; let slow = 0;
  const draw = (u32) => {
    for (;;) {
      const a = u32() >>> 0, b = u32() >>> 0;
      let l = 0, r = k; // first j with X < cum[j]; prefix comparison
      while (l < r) { const m = (l + r) >> 1; if (a < hi[m] || (a === hi[m] && b < lo[m])) r = m; else l = m + 1; }
      // l = first j with top(cum[j]) > prefix. If some j < l has top(cum[j]) == prefix, decide exactly.
      if (l > 0 && hi[l - 1] === a && lo[l - 1] === b) {
        slow += 1;
        let rest = 0n; for (let got = 0n; got < sh; got += 32n) rest = (rest << 32n) | BigInt(u32() >>> 0);
        const extra = (sh + 31n) / 32n * 32n - sh; rest >>= extra; // keep exactly L - 64 bits
        const X = ((BigInt(a) << 32n | BigInt(b)) << sh) | rest;
        let j = 0; while (j < k && X >= cum[j]) j++;
        if (j === k) continue; // X >= den·2^s: reject
        return j;
      }
      if (l === k) continue; // reject
      return l;
    }
  };
  return { draw, k, stats: () => ({ slow }) };
}

const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const fileSha = (u) => sha(readFileSync(new URL(u, import.meta.url)));
export const codeDigests = () => ({ statistic: fileSha('../statistic/wave1-statistic.mjs'), sampler: fileSha('./dt-mc.mjs'), adapter: fileSha('../labkit/aes-ctr-ref.mjs') });
export const cellOrderDigest = (lumped) => sha(`${lumped.den.toString(16)}|${lumped.cellNum.map((x) => x.toString(16)).join(',')}`);

// NULL manifest: everything fixed before the evidence run; NO observed X² (that goes into a separate commit).
export function nullManifest({ entryIndex, e, M, lumped, keyId, keyHex }) {
  if (e.kind !== 'dup') throw new Error('K2: exact per-observation sampler is for duplicates entries only');
  return { schema: 'open-rng-engine/r-dt-mc/null-manifest/v1', entry_index: entryIndex, entry: e.id, M,
    domain: MC.DOMAIN, iv_scheme: 'BE32(domain) || BE32(entry << 11 | block) || 0^64', key_id: keyId, key_sha256: sha(Buffer.from(keyHex, 'hex')),
    B: MC.B, B_plus_1: MC.B_PLUS_1, block_size: MC.BLOCK, n_blocks: nBlocks(), flag_max_ge: MC.FLAG_MAX_GE, ties: '>=',
    cells: lumped.cellNum.length, cell_order_sha256: cellOrderDigest(lumped), digests: codeDigests() };
}
export const manifestSha = (m) => sha(JSON.stringify(m));

// G-71 (HoQ A10): the observed X² is computed HERE from the observed count vector (lumped cell order of THE
// module), through S.pearson with the same lumping and M; a scalar from outside is refused. M must equal the sum
// of the observed counts, and M > 10^9 is refused until Quant rechecks KL_safe at that scale.
export const M_MAX = 1e9;
export function observedX2(man, lumped, observed) {
  if (observed === null || typeof observed !== 'object' || !Array.isArray(observed.counts)) throw new Error('R-DT-MC: observed must be { counts: [...] } in lumped cell order; a scalar X² is refused (G-71)');
  const c = observed.counts; const k = lumped.cellNum.length;
  if (c.length !== k || !c.every((x) => Number.isSafeInteger(x) && x >= 0)) throw new Error(`R-DT-MC: observed counts must be ${k} non-negative integers (G-71)`);
  const M = c.reduce((a, x) => a + x, 0);
  if (M !== man.M) throw new Error(`R-DT-MC: manifest M ${man.M} != sum of observed counts ${M} (G-71)`);
  if (man.M > M_MAX) throw new Error('R-DT-MC: M > 10^9 refused until Quant rechecks KL_safe (G-71)');
  const first = new Int32Array(k).fill(-1); for (let i = 0; i < lumped.map.length; i++) if (first[lumped.map[i]] < 0) first[lumped.map[i]] = i;
  const h = new Float64Array(lumped.map.length); for (let j = 0; j < k; j++) h[first[j]] = c[j];
  return { x2: S.pearson(h, lumped, man.M).x2, observed_sha256: sha(JSON.stringify(c)) };
}
// G-67 (HoQ A9): the manifest's B, B+1, block size and block count must be the R-DT-MC constants.
export function checkManifestConstants(man) {
  if (man.B !== MC.B || man.B_plus_1 !== MC.B_PLUS_1 || man.block_size !== MC.BLOCK || man.n_blocks !== nBlocks()) throw new Error(`R-DT-MC: manifest B ${man.B} / B+1 ${man.B_plus_1} / block ${man.block_size} / blocks ${man.n_blocks} differ from the constants (G-67)`);
}
const geOf = (x2s, x2obs) => { let ge = 0; for (const x of x2s) if (exceeds(x, x2obs)) ge += 1; return ge; };

// One block: block_size replications of the exact null, X² through THE module, #>= against the observed X².
export function runBlock(man, lumped, keyHex, block, observed) {
  const { x2: x2obs, observed_sha256 } = observedX2(man, lumped, observed);
  const reps = blockReps(block, man.B, man.block_size);
  const s = mcStream(keyHex, man.entry_index, block); const u32 = () => s.u32();
  const smp = exactSampler(lumped); const k = smp.k;
  const first = new Int32Array(k).fill(-1); for (let i = 0; i < lumped.map.length; i++) if (first[lumped.map[i]] < 0) first[lumped.map[i]] = i;
  const h = new Float64Array(lumped.map.length); const x2s = new Float64Array(reps);
  for (let r = 0; r < reps; r++) {
    const c = new Float64Array(k); for (let o = 0; o < man.M; o++) c[smp.draw(u32)] += 1;
    for (let j = 0; j < k; j++) h[first[j]] = c[j];
    x2s[r] = S.pearson(h, lumped, man.M).x2;
  }
  return { block, reps, ge: geOf(x2s, x2obs), x2obs, observed_sha256, x2: Array.from(x2s), x2_sha256: sha(Buffer.from(x2s.buffer)), manifest_sha256: manifestSha(man) };
}
const blockDigest = (x) => sha(JSON.stringify([x.block, x.reps, x.ge, x.x2obs, x.observed_sha256, x.x2_sha256, x.manifest_sha256]));
export const chainNext = (prev, x) => sha(`${prev}|${blockDigest(x)}`);
export const CHAIN_SEED = '0'.repeat(64);
function verifyBlock(x, b, man, ms, obs) {
  if (x.manifest_sha256 !== ms || x.block !== b || x.reps !== blockReps(b, man.B, man.block_size)) return 'stale';
  if (x.observed_sha256 !== obs.observed_sha256 || x.x2obs !== obs.x2) throw new Error(`R-DT-MC: block ${b} was computed for another observed vector (G-67)`);
  if (!Array.isArray(x.x2) || x.x2.length !== x.reps || sha(Buffer.from(Float64Array.from(x.x2).buffer)) !== x.x2_sha256) throw new Error(`R-DT-MC: block ${b} X² content does not match its digest (G-67)`);
  if (geOf(x.x2, obs.x2) !== x.ge) throw new Error(`R-DT-MC: block ${b} #>= does not match its stored X² (G-67)`);
  return 'ok';
}

// Resumable driver (per entry, per block): constants, digests, key and observed vector checked at start; valid
// block files are kept; each block is written atomically (tmp + rename) with its chain link. Assembly re-verifies
// every block and the chain. Returns the assembled p_MC and the chain head once all blocks exist.
export function runEntry(man, lumped, keyHex, observed, dir, { maxBlocks = Infinity } = {}) {
  checkManifestConstants(man);
  const d = codeDigests();
  for (const f of ['statistic', 'sampler', 'adapter']) if (d[f] !== man.digests[f]) throw new Error(`R-DT-MC: ${f} digest differs from the null manifest`);
  if (cellOrderDigest(lumped) !== man.cell_order_sha256) throw new Error('R-DT-MC: cell order differs from the null manifest');
  if (sha(Buffer.from(keyHex, 'hex')) !== man.key_sha256) throw new Error('R-DT-MC: key differs from the null manifest');
  const obs = observedX2(man, lumped, observed);
  mkdirSync(dir, { recursive: true }); const ms = manifestSha(man); let done = 0;
  const file = (b) => join(dir, `block-${String(b).padStart(4, '0')}.json`);
  for (let b = 0; b < man.n_blocks; b++) {
    if (existsSync(file(b)) && verifyBlock(JSON.parse(readFileSync(file(b), 'utf8')), b, man, ms, obs) === 'ok') continue;
    if (done >= maxBlocks) return null;
    const out = runBlock(man, lumped, keyHex, b, observed);
    writeFileSync(`${file(b)}.tmp`, JSON.stringify(out) + '\n'); renameSync(`${file(b)}.tmp`, file(b)); done += 1;
  }
  let ge = 0, reps = 0, chain = CHAIN_SEED;
  for (let b = 0; b < man.n_blocks; b++) {
    const x = JSON.parse(readFileSync(file(b), 'utf8'));
    if (verifyBlock(x, b, man, ms, obs) !== 'ok') throw new Error(`R-DT-MC: block ${b} stale at assembly (G-67)`);
    ge += x.ge; reps += x.reps; chain = chainNext(chain, x);
  }
  if (reps !== man.B) throw new Error(`R-DT-MC: ${reps} replications assembled, manifest B ${man.B}`);
  return { ge, reps, p_mc: (1 + ge) / (man.B + 1), flag: mcFlag(ge), x2obs: obs.x2, observed_sha256: obs.observed_sha256, chain_head: chain };
}
