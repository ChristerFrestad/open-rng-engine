// labkit reference adapter: AES-256-CTR (HoQ addendum 1 A6 / A7 R-W1-METHOD; CTO commit H).
// Calibration only. It lives OUTSIDE src/ and outside the engine code path: no engine module imports it, and
// rule 27 keeps src/ from importing it (test/labkit-calibration.test.mjs). It never draws OS entropy: the
// stream is a pure function of the pinned key and a 128-bit initial counter block.
//   keystream = AES-256-CTR(KEY, IV) over zero plaintext; IV = BE32(stream) || BE32(rep) || 0^64, and the
//   128-bit block counter increments as in NIST SP 800-38A (F.5.5 KAT below, read from the PDF, sha256
//   66821162de1e7130c5fb5eedb22140d8d6d013ec51af4550bb095c2a9481a00e).
//   u32 = little-endian 32-bit words of the keystream, in order.
//   below(r): uniform on [0, r) by rejection (r <= 2^32: u < 2^32 - (2^32 mod r), value u mod r;
//   r = 2^32 + 1: x = (u1 & 1)*2^32 + u2, reject x >= r; r = 2^48: (u1 & 0xffff)*2^32 + u2, no rejection).
import { createCipheriv, createHash } from 'node:crypto';

export const ADAPTER_ID = 'labkit-ref/aes-256-ctr/v1';
// KEY = sha256("open-rng-engine labkit reference AES-256-CTR key v1")
export const KEY_HEX = '4e93c44f26d655731512adfe11534a18a0c25ec729259b092fdbb2228133f737';
export const NIST_F55 = Object.freeze({
  key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  iv: 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
  plaintext: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
  ciphertext: '601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6',
});
const TWO32 = 4294967296;
const CHUNK = 1 << 20; // bytes of keystream per refill

export function ivFor(stream, rep) {
  const iv = Buffer.alloc(16);
  iv.writeUInt32BE(stream >>> 0, 0);
  iv.writeUInt32BE(rep >>> 0, 4);
  return iv;
}

export function aesCtr(keyHex, ivBuf, data) {
  const c = createCipheriv('aes-256-ctr', Buffer.from(keyHex, 'hex'), ivBuf);
  return Buffer.concat([c.update(data), c.final()]);
}

export class RefStream {
  constructor(stream, rep, keyHex = KEY_HEX) {
    this.cipher = createCipheriv('aes-256-ctr', Buffer.from(keyHex, 'hex'), ivFor(stream, rep));
    this.zero = Buffer.alloc(CHUNK);
    this.w = null; this.i = 0; this.words = 0;
  }
  refill() {
    const b = this.cipher.update(this.zero);
    this.w = new Uint32Array(b.buffer, b.byteOffset, b.byteLength >>> 2);
    this.i = 0; this.words += this.w.length;
  }
  u32() {
    if (this.w === null || this.i === this.w.length) this.refill();
    return this.w[this.i++];
  }
  below(r) {
    if (r <= TWO32) {
      if (r === TWO32) return this.u32();
      const lim = TWO32 - (TWO32 % r);
      for (;;) { const u = this.u32(); if (u < lim) return u % r; }
    }
    if (r === TWO32 + 1) {
      for (;;) { const x = (this.u32() & 1) * TWO32 + this.u32(); if (x < r) return x; }
    }
    if (r === 2 ** 48) return (this.u32() & 0xffff) * TWO32 + this.u32();
    throw new Error(`below: unsupported range ${r}`);
  }
}

// Self-KATs of this adapter (pinned in test/labkit-calibration.test.mjs).
export function selfKat() {
  const s = new RefStream(0, 0);
  const first8 = Array.from({ length: 8 }, () => s.u32());
  const mib = aesCtr(KEY_HEX, ivFor(0, 0), Buffer.alloc(1 << 20));
  const t = new RefStream(1, 2);
  const below54 = Array.from({ length: 10 }, () => t.below(54));
  const big = [t.below(TWO32 + 1), t.below(2 ** 48), t.below(2 ** 31 + 1)];
  return { first8, mib: createHash('sha256').update(mib).digest('hex'), below54, big };
}
