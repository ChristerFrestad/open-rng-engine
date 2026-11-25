// R-G64 (design verification/r-g64-design.md §3; HoQ addendum 1 A22 / D22-4..6). The fd-3 frame format
// between one evidence helper and the launcher, and the exact binary codec for one public-call outcome.
// A frame is [type u8][length u32 LE][payload]. Types: H (header, JSON), D (outcome bytes), T (trailer, JSON).
// Pure module: no I/O, no entropy. The launcher decodes every D payload itself; nothing a helper claims about
// its own output is believed (G-64).
import { createHash } from 'node:crypto';

export const FRAME = Object.freeze({ H: 0x48, D: 0x44, T: 0x54 });
export const MAX_JSON = 1 << 16;
export const MAX_DATA = 1 << 20;

export function frame(type, payload) {
  const b = Buffer.allocUnsafe(5 + payload.length);
  b[0] = type; b.writeUInt32LE(payload.length, 1); (Buffer.isBuffer(payload) ? payload : Buffer.from(payload)).copy(b, 5);
  return b;
}
export const jsonFrame = (type, obj) => frame(type, Buffer.from(JSON.stringify(obj), 'utf8'));

// Incremental decoder. push(chunk) returns the complete frames; any malformed input throws (integrity void).
export class FrameReader {
  constructor() { this.buf = Buffer.alloc(0); this.bytes = 0; }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    this.bytes += chunk.length;
    const out = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const type = this.buf[0], len = this.buf.readUInt32LE(1);
      if (type !== FRAME.H && type !== FRAME.D && type !== FRAME.T) throw new Error(`frame: unknown type 0x${type.toString(16)}`);
      if (len > (type === FRAME.D ? MAX_DATA : MAX_JSON)) throw new Error(`frame: ${String.fromCharCode(type)} payload ${len} over its limit`);
      if (this.buf.length < 5 + len) break;
      const payload = this.buf.subarray(5, 5 + len);
      this.buf = this.buf.subarray(5 + len);
      out.push(type === FRAME.D ? { type, payload } : { type, json: parseJson(payload) });
    }
    return out;
  }
  end() { if (this.buf.length) throw new Error(`frame: ${this.buf.length} trailing bytes after the last frame`); }
}
function parseJson(p) {
  try { const o = JSON.parse(p.toString('utf8')); if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new Error('not an object'); return o; }
  catch (e) { throw new Error(`frame: JSON payload unreadable (${e.message})`); }
}

// ---------------- outcome codec (exact; D22-6: nothing is hashed or truncated on the wire) ----------------
const widthFor = (maxExclusive) => (maxExclusive <= 2 ** 8 ? 1 : maxExclusive <= 2 ** 16 ? 2 : maxExclusive <= 2 ** 32 ? 4 : 8);
const iota = (n) => Array.from({ length: n }, (_, i) => i);
export function weightsFor(k) {
  const p = k.parameters || {};
  if (Array.isArray(p.weights)) return p.weights;
  if (p.strip === 'W-A') return iota(64).map((i) => i + 1);
  if (p.strip === 'W-B') return iota(64).map((i) => i % 8);
  throw new Error(`no weights for ${k.id}`);
}
// One call shape per K entry. Tuple entries are w calls of the same shape (the window is read by the consumer).
export function shapeKey(k) {
  const p = k.parameters || {};
  switch (k.primitive) {
    case 'randomInt': return `randomInt [${p.min},${p.max})`;
    case 'shuffle': return `shuffle n=${p.n ?? 52}`;
    case 'sample': return `sample n=${p.n} k=${p.k}`;
    case 'weightedPick': return `weightedPick ${Array.isArray(p.weights) ? `[${p.weights}]` : p.strip}`;
    default: throw new Error(`unknown primitive ${String(k.primitive)}`);
  }
}
export function codecFor(k) {
  const p = k.parameters || {};
  let values, bound, array;
  switch (k.primitive) {
    case 'randomInt': values = 1; bound = Number(p.max); array = false; break;
    case 'weightedPick': values = 1; bound = weightsFor(k).length; array = false; break;
    case 'shuffle': values = p.n ?? 52; bound = values; array = true; break;
    case 'sample': values = p.k; bound = p.n; array = true; break;
    default: throw new Error(`unknown primitive ${String(k.primitive)}`);
  }
  const w = widthFor(bound);
  const bytes = values * w;
  const put = (x, b, o) => {
    if (!Number.isSafeInteger(x) || x < 0 || x >= bound) throw new Error(`codec: value ${x} outside [0, ${bound})`);
    if (w === 1) b[o] = x; else if (w === 2) b.writeUInt16LE(x, o); else if (w === 4) b.writeUInt32LE(x, o);
    else { b.writeUInt32LE(x % 2 ** 32, o); b.writeUInt32LE(Math.floor(x / 2 ** 32), o + 4); }
  };
  const get = (b, o) => {
    if (w === 1) return b[o]; if (w === 2) return b.readUInt16LE(o); if (w === 4) return b.readUInt32LE(o);
    const hi = b.readUInt32LE(o + 4); if (hi >= 2 ** 21) throw new Error('codec: 8-byte value over 2^53');
    return hi * 2 ** 32 + b.readUInt32LE(o);
  };
  return Object.freeze({
    shape: shapeKey(k), values, width: w, bytes,
    encode(v, b, o) { if (array) { if (!Array.isArray(v) || v.length !== values) throw new Error('codec: outcome length'); for (let i = 0; i < values; i++) put(v[i], b, o + i * w); } else put(v, b, o); },
    decode(b, o) { if (!array) return get(b, o); const v = new Array(values); for (let i = 0; i < values; i++) v[i] = get(b, o + i * w); return v; },
  });
}

// D22-6: a key for one outcome. Outcomes of at most 128 bits are kept exactly (their bytes, hex); longer ones
// use sha256 truncated to 128 bits. Every duplicate-style comparison over whole outcomes goes through this.
export function outcomeKey(bytes) {
  return bytes.length <= 16 ? `x${Buffer.from(bytes).toString('hex')}` : `h${createHash('sha256').update(bytes).digest('hex').slice(0, 32)}`;
}
