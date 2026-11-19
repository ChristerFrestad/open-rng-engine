// CTO commit H (HoQ addendum 1 A6, A7 R-W1-METHOD): labkit AES-256-CTR reference adapter and the wave-1
// calibration harness. Calibration is verification on the reference stream, not a counted evidence run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ref from '../verification/labkit/aes-ctr-ref.mjs';
import * as L from '../verification/calibration/laws.mjs';
import * as W from '../verification/calibration/wave1-entries.mjs';
import { scanFile } from '../tools/ci/import-allowlist.mjs';
import { isUnderRepoSrc, defaultAllowedCallers } from '../tools/ci/entropy-backstop.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const sha = (rel) => createHash('sha256').update(readFileSync(join(ROOT, rel))).digest('hex');

test('labkit adapter: pinned digest, key and NIST SP 800-38A F.5.5 CTR-AES256 KAT', () => {
  assert.equal(sha('verification/labkit/aes-ctr-ref.mjs'), 'ae7a25d3d2a2529c746a6660af65efb816425786eb92cdcf546c8b793d0cc956');
  assert.equal(ref.KEY_HEX, createHash('sha256').update('open-rng-engine labkit reference AES-256-CTR key v1').digest('hex'));
  const k = ref.NIST_F55;
  assert.equal(ref.aesCtr(k.key, Buffer.from(k.iv, 'hex'), Buffer.from(k.plaintext, 'hex')).toString('hex'), k.ciphertext);
});

test('labkit adapter: own KAT vectors (keystream words, 1 MiB digest, below())', () => {
  assert.deepEqual(ref.selfKat(), {
    first8: [740981066, 2562251472, 3131492374, 232516785, 3435534316, 501044322, 176904737, 798519875],
    mib: '7988cc4e88d358f543bd9c841a968cb1874b4d7bd4b1ec3fda7456eda05279cb',
    below54: [26, 39, 51, 9, 14, 39, 2, 47, 19, 27],
    big: [1163318028, 128789884501595, 2135996307],
  });
});

test('labkit adapter stays outside src: rule 27 refuses a src import of it; backstop src scope unchanged', () => {
  for (const spec of ['../verification/labkit/aes-ctr-ref.mjs', '../verification/labkit/aes-ctr-ref.ts', '../verification/calibration/laws.mjs']) {
    const r = scanFile('src/zz-labkit.ts', `import { x } from '${spec}';\nexport const y = x;\n`);
    assert.ok(r.hits.some((h) => /rule27-specifier-not-allowed/.test(h)), spec);
  }
  assert.equal(isUnderRepoSrc(join(ROOT, 'src/index.ts')), true);
  assert.equal(isUnderRepoSrc(join(ROOT, 'verification/labkit/aes-ctr-ref.mjs')), false);
  assert.equal(JSON.stringify(defaultAllowedCallers()).includes('labkit'), false);
  for (const f of ['verification/labkit/aes-ctr-ref.mjs', 'verification/calibration/laws.mjs', 'verification/calibration/wave1-entries.mjs']) {
    assert.doesNotMatch(readFileSync(join(ROOT, f), 'utf8'), /from '\.\.\/\.\.\/src\/|randomBytes|randomFill|getRandomValues/);
  }
});

const perms = (a) => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));

test('calibration laws: brute-force enumeration fixtures (coupon d=2,3; duplicates m=3 b=5; adjacency 2x3, 3x2)', () => {
  const c2 = L.couponLaw(2).p; for (let k = 2; k < 12; k++) assert.ok(Math.abs(c2[k - 2] - 0.5 ** (k - 1)) < 1e-15);
  // d = 3: enumerate all 3^t sequences up to t = 9 and read T exactly.
  const c3 = L.couponLaw(3).p; const cnt = new Map();
  for (let t = 3; t <= 9; t++) { let n = 0; for (let x = 0; x < 3 ** t; x++) { const s = new Set(); let v = x, T = 0; for (let i = 0; i < t; i++) { s.add(v % 3); v = Math.floor(v / 3); if (s.size === 3) { T = i + 1; break; } } if (T === t) n += 1; } cnt.set(t, n / 3 ** t); }
  for (const [t, q] of cnt) assert.ok(Math.abs(c3[t - 3] - q) < 1e-14, `coupon d=3 T=${t}`);
  const dl = L.dupLaw(3, 5).p; const h = new Array(6).fill(0);
  for (let x = 0; x < 3 ** 5; x++) { const s = new Set(); let v = x, C = 0; for (let i = 0; i < 5; i++) { if (s.has(v % 3)) C += 1; else s.add(v % 3); v = Math.floor(v / 3); } h[C] += 1 / 3 ** 5; }
  for (let c = 0; c <= 4; c++) assert.ok(Math.abs((dl[c] ?? 0) - h[c]) < 1e-14, `dup C=${c}`);
  for (const [Lb, c] of [[2, 3], [3, 2]]) {
    const law = L.adjacencyLawExact(Lb, c); const deck = Array.from({ length: Lb * c }, (_, i) => Math.floor(i / c));
    const hh = new Map(); for (const p of perms(deck.map((_, i) => i))) { let X = 0; for (let i = 1; i < p.length; i++) if (deck[p[i]] === deck[p[i - 1]]) X += 1; hh.set(X, (hh.get(X) ?? 0n) + 1n); }
    for (const [X, n] of hh) assert.equal(law.exactNum.get(X), n, `adjacency ${Lb}x${c} X=${X}`);
  }
  const a4 = L.adjacencyLawExact(4, 13); assert.equal([...a4.exactNum.values()].reduce((x, y) => x + y, 0n), a4.total);
});

test('calibration: chi^2 tail at the K threshold, Lehmer top-20 exact against BigInt rank', () => {
  assert.ok(Math.abs(L.chi2sf(30.943101458355866, 7) - 0.01 / 157) < 1e-12);
  const F = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };
  for (let i = 0; i < 300; i++) {
    const got = W.lehmerTop20(new ref.RefStream(99, i), new Uint8Array(52));
    const s = new ref.RefStream(99, i); const a = Array.from({ length: 52 }, (_, k) => k);
    for (let j = 0; j < 52; j++) { const r = j + s.below(52 - j); [a[j], a[r]] = [a[r], a[j]]; }
    let rank = 0n; for (let j = 0; j < 52; j++) { let d = 0; for (let k = j + 1; k < 52; k++) if (a[k] < a[j]) d += 1; rank += BigInt(d) * F(51 - j); }
    assert.equal(got, Number((rank * 1048576n) / F(52)));
  }
});

