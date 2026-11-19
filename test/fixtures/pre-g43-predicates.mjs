// Vendored pre-G-43 predicate implementations copied from commit
// 0a94759f4a486d796b020d457abaf046475f3051 (types erased). Used only by
// test/g43-predicate-reword.test.mjs to prove the live reword is behaviour-identical.
// Do not import from production code.

export const MAX_DATA = 65520;
export const FINGERPRINT_BYTES = 16;
export const MAX_WIDTH = MAX_DATA + FINGERPRINT_BYTES;

export function isValidBlockPlanN(n) {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 1;
}

function assertN(n) {
  if (!isValidBlockPlanN(n)) throw new RangeError('RANGE_INVALID: blockPlan(n) requires a safe integer n >= 1');
}

export function blockCount(n) {
  assertN(n);
  return Math.ceil(n / MAX_DATA);
}

export function blockWidthAt(n, i) {
  assertN(n);
  const count = Math.ceil(n / MAX_DATA);
  if (!Number.isSafeInteger(i) || i < 0 || i >= count) throw new RangeError('RANGE_INVALID: block index out of range');
  const data = i < count - 1 ? MAX_DATA : n - MAX_DATA * (count - 1);
  return data + FINGERPRINT_BYTES;
}

export function blockPlanTotal(n) {
  assertN(n);
  return n + FINGERPRINT_BYTES * Math.ceil(n / MAX_DATA);
}

export function blockPlan(n) {
  assertN(n);
  const widths = [];
  let remaining = n;
  while (remaining > 0) {
    const data = Math.min(remaining, MAX_DATA);
    widths.push(data + FINGERPRINT_BYTES);
    remaining -= data;
  }
  return widths;
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAPPING_KINDS = new Set(['randomInt', 'shuffle', 'sample', 'weightedPick']);
const MAPPING_READ = /^(?:[0-9a-f]{8}|[0-9a-f]{14})$/;
const LOWER_HEX = /^[0-9a-f]*$/;

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function hasOwn(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function isIntIn(v, lo, hi) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= lo && v <= hi;
}

function field(o, k) {
  if (!hasOwn(o, k)) return undefined;
  if (k === 'kind') return o.kind;
  if (k === 'params') return o.params;
  if (k === 'reads') return o.reads;
  if (k === 'bytesFetched') return o.bytesFetched;
  if (k === 'output') return o.output;
  if (k === 'n') return o.n;
  if (k === 'width') return o.width;
  if (k === 'count') return o.count;
  return undefined;
}

export function validateReadsOutputSchema(e) {
  const parsed = parseReadsOutput(e);
  return parsed.ok ? null : parsed.detail;
}

function parseReadsOutput(e) {
  if (!isPlainObject(e)) return { ok: false, detail: 'evidence is not an object' };
  for (const k of ['kind', 'params', 'reads', 'bytesFetched']) if (!hasOwn(e, k)) return { ok: false, detail: `missing ${k}` };
  const kind = field(e, 'kind');
  if (kind !== 'randomBytes' && !(typeof kind === 'string' && MAPPING_KINDS.has(kind))) return { ok: false, detail: 'unknown kind' };
  const params = field(e, 'params');
  if (!isPlainObject(params)) return { ok: false, detail: 'params is not an object' };
  const bytesFetched = field(e, 'bytesFetched');
  if (!isIntIn(bytesFetched, 0, MAX_SAFE)) return { ok: false, detail: 'bytesFetched is not a safe non-negative integer' };
  const readsVal = field(e, 'reads');
  if (!Array.isArray(readsVal)) return { ok: false, detail: 'reads is not an array' };
  if (kind !== 'randomBytes') {
    if (hasOwn(e, 'output')) return { ok: false, detail: 'output present on a mapping primitive' };
    for (const r of readsVal) if (typeof r !== 'string' || !MAPPING_READ.test(r)) return { ok: false, detail: 'mapping read is not 8 or 14 lowercase hex' };
    return { ok: true, mapping: true };
  }
  if (!hasOwn(params, 'n') || !isIntIn(field(params, 'n'), 0, MAX_SAFE)) return { ok: false, detail: 'params.n is not a safe non-negative integer' };
  const n = field(params, 'n');
  if (!isValidBlockPlanN(n)) return { ok: false, detail: 'params.n must be >= 1 (PLAN L605: n = 0 throws RANGE_INVALID, no evidence)' };
  if (!hasOwn(e, 'output')) return { ok: false, detail: 'missing output' };
  const output = field(e, 'output');
  if (typeof output !== 'string') return { ok: false, detail: 'output is not a string' };
  const reads = [];
  for (let i = 0; i < readsVal.length; i++) {
    const r = readsVal[i];
    if (!isPlainObject(r)) return { ok: false, detail: `reads[${i}] is not an object` };
    const keys = Object.keys(r);
    if (keys.length !== 2 || !hasOwn(r, 'width') || !hasOwn(r, 'count')) return { ok: false, detail: `reads[${i}] must be exactly {width, count}` };
    const width = field(r, 'width');
    const count = field(r, 'count');
    if (!isIntIn(width, 17, 65536)) return { ok: false, detail: `reads[${i}].width not an integer in 17..65536` };
    if (!isIntIn(count, 17, 65536)) return { ok: false, detail: `reads[${i}].count not an integer in 17..65536` };
    reads.push({ width, count });
  }
  return { ok: true, mapping: false, ev: { kind: 'randomBytes', n, output, reads, bytesFetched } };
}

export function checkRandomBytesReplay(e) {
  if (isPlainObject(e) && field(e, 'kind') === 'randomBytes') {
    const params = field(e, 'params');
    const n = isPlainObject(params) && hasOwn(params, 'n') ? field(params, 'n') : undefined;
    if (!isValidBlockPlanN(n)) return { ok: false, code: 'R0', detail: `params.n ${JSON.stringify(n) ?? 'missing'} is not a safe integer >= 1 (PLAN L605: n = 0 throws RANGE_INVALID, no evidence)`, failures: ['R0'] };
  }
  const parsed = parseReadsOutput(e);
  if (!parsed.ok) return { ok: false, code: 'R1', detail: parsed.detail, failures: ['R1'] };
  if (parsed.mapping) return { ok: false, code: 'R1', detail: 'kind is not randomBytes', failures: ['R1'] };
  const ev = parsed.ev;
  const n = ev.n;
  const output = ev.output;
  const reads = ev.reads;
  const bytesFetched = ev.bytesFetched;
  const found = [];

  if (output.length !== 2 * n) found.push(['R2', `output has ${output.length} hex chars, expected 2n = ${2 * n}`]);
  if (output.length % 2 !== 0 || !LOWER_HEX.test(output)) found.push(['R3', 'output is not lowercase even-length hex (no prefix, no separators)']);

  const blocks = blockCount(n);
  if (reads.length !== blocks) {
    found.push(['R4', `reads.length ${reads.length} !== blockPlan(n).length ${blocks}`]);
  } else {
    for (let i = 0; i < blocks; i++) {
      const rec = reads[i];
      if (rec === undefined) break;
      const w = blockWidthAt(n, i);
      if (rec.width !== w) { found.push(['R4', `reads[${i}].width ${rec.width} !== blockPlan(n)[${i}] ${w}`]); break; }
    }
  }
  let sum = 0;
  let r5 = false;
  for (let i = 0; i < reads.length; i++) {
    const rec = reads[i];
    if (rec === undefined) continue;
    if (!r5 && rec.count !== rec.width) { found.push(['R5', `reads[${i}].count ${rec.count} !== width ${rec.width}`]); r5 = true; }
    sum += rec.count;
  }
  if (sum !== bytesFetched) found.push(['R6', `Σcount ${sum} !== bytesFetched ${bytesFetched}`]);
  const total = blockPlanTotal(n);
  if (bytesFetched !== total) found.push(['R7', `bytesFetched ${bytesFetched} !== n + 16·⌈n/65520⌉ = ${total}`]);

  if (found.length === 0) return { ok: true };
  const first = found[0];
  if (first === undefined) return { ok: true };
  const code = first[0];
  const detail = first[1];
  return { ok: false, code, detail, failures: found.map((row) => row[0]) };
}
