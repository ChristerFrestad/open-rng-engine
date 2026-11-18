// R-93 replay invariant checker for audited `randomBytes` evidence (PLAN R-93 L203, R-61 L169, R-56 L164;
// cto-g1-spec.md §5.2–§5.4; CPO-R98 / C-11, DECISIONS L77). VERIFICATION BUILD ONLY (src/verify/, rule 24).
// Pure function: never fetches, no I/O, no clock, no state. The context check (CONTEXT_MISMATCH, §3.11)
// runs before this in the full replay and is out of scope here.
// Order (first failure wins): R0 n is a safe integer >= 1 (CPO-R99 O-69; spec errata E-1), R1 schema, R2 len(output)==n, R3 lowercase even-length hex, R4 reads vs blockPlan(n),
// R5 count===width per entry, R6 Σcount===bytesFetched, R7 bytesFetched===n+16·⌈n/65520⌉.
// R1 checks the §5.2 shape except the `output` hex pattern, which is reported as R3 so each invariant is observable.

import { blockCount, blockWidthAt, blockPlanTotal, isValidBlockPlanN } from '../entropy/blockPlan.ts';

export type ReplayCode = 'R0' | 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7';
export type ReplayResult = { ok: true } | { ok: false; code: ReplayCode; detail: string; failures: ReplayCode[] };

// Closed JSON-like input (G-28: no `unknown` / `any`, no type assertions, no non-null `!`).
export type Incoming = IncomingDict | Incoming[] | string | number | boolean | null | undefined;
export type IncomingDict = {
  kind?: Incoming;
  params?: Incoming;
  reads?: Incoming;
  bytesFetched?: Incoming;
  output?: Incoming;
  n?: Incoming;
  width?: Incoming;
  count?: Incoming;
};

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAPPING_KINDS: ReadonlySet<string> = new Set(['randomInt', 'shuffle', 'sample', 'weightedPick']);
const MAPPING_READ = /^(?:[0-9a-f]{8}|[0-9a-f]{14})$/;
const LOWER_HEX = /^[0-9a-f]*$/;

function isPlainObject(v: Incoming): boolean {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function hasOwn(o: IncomingDict, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function isIntIn(v: Incoming, lo: number, hi: number): boolean {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= lo && v <= hi;
}

function field(o: IncomingDict, k: string): Incoming {
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

type ReadRec = { width: number; count: number };
type ParsedRandomBytes = { kind: 'randomBytes'; n: number; output: string; reads: ReadRec[]; bytesFetched: number };

/** §5.2 reads/output shape for any kind (randomBytes branch and mapping branch). Hex pattern of `output` excluded (R3). */
export function validateReadsOutputSchema(e: Incoming): string | null {
  const parsed = parseReadsOutput(e);
  return parsed.ok ? null : parsed.detail;
}

function parseReadsOutput(e: Incoming):
  | { ok: true; mapping: true }
  | { ok: true; mapping: false; ev: ParsedRandomBytes }
  | { ok: false; detail: string } {
  if (!isPlainObject(e)) return { ok: false, detail: 'evidence is not an object' };
  if (typeof e !== 'object' || e === null || Array.isArray(e)) return { ok: false, detail: 'evidence is not an object' };
  for (const k of ['kind', 'params', 'reads', 'bytesFetched']) if (!hasOwn(e, k)) return { ok: false, detail: `missing ${k}` };
  const kind = field(e, 'kind');
  if (kind !== 'randomBytes' && !(typeof kind === 'string' && MAPPING_KINDS.has(kind))) return { ok: false, detail: 'unknown kind' };
  const params = field(e, 'params');
  if (!isPlainObject(params)) return { ok: false, detail: 'params is not an object' };
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return { ok: false, detail: 'params is not an object' };
  const bytesFetched = field(e, 'bytesFetched');
  if (!isIntIn(bytesFetched, 0, MAX_SAFE) || typeof bytesFetched !== 'number') return { ok: false, detail: 'bytesFetched is not a safe non-negative integer' };
  const readsVal = field(e, 'reads');
  if (!Array.isArray(readsVal)) return { ok: false, detail: 'reads is not an array' };
  if (kind !== 'randomBytes') {
    if (hasOwn(e, 'output')) return { ok: false, detail: 'output present on a mapping primitive' };
    for (const r of readsVal) if (typeof r !== 'string' || !MAPPING_READ.test(r)) return { ok: false, detail: 'mapping read is not 8 or 14 lowercase hex' };
    return { ok: true, mapping: true };
  }
  if (!hasOwn(params, 'n') || !isIntIn(field(params, 'n'), 0, MAX_SAFE)) return { ok: false, detail: 'params.n is not a safe non-negative integer' };
  const n = field(params, 'n');
  if (!isValidBlockPlanN(n) || typeof n !== 'number') return { ok: false, detail: 'params.n must be >= 1 (PLAN L605: n = 0 throws RANGE_INVALID, no evidence)' };
  if (!hasOwn(e, 'output')) return { ok: false, detail: 'missing output' };
  const output = field(e, 'output');
  if (typeof output !== 'string') return { ok: false, detail: 'output is not a string' };
  const reads: ReadRec[] = [];
  for (let i = 0; i < readsVal.length; i++) {
    const r = readsVal[i];
    if (!isPlainObject(r)) return { ok: false, detail: `reads[${i}] is not an object` };
    if (typeof r !== 'object' || r === null || Array.isArray(r)) return { ok: false, detail: `reads[${i}] is not an object` };
    const keys = Object.keys(r);
    if (keys.length !== 2 || !hasOwn(r, 'width') || !hasOwn(r, 'count')) return { ok: false, detail: `reads[${i}] must be exactly {width, count}` };
    const width = field(r, 'width');
    const count = field(r, 'count');
    if (!isIntIn(width, 17, 65536) || typeof width !== 'number') return { ok: false, detail: `reads[${i}].width not an integer in 17..65536` };
    if (!isIntIn(count, 17, 65536) || typeof count !== 'number') return { ok: false, detail: `reads[${i}].count not an integer in 17..65536` };
    reads.push({ width, count });
  }
  return { ok: true, mapping: false, ev: { kind: 'randomBytes', n, output, reads, bytesFetched } };
}

/**
 * R-93 replay invariants R0..R7 for kind = randomBytes. Never fetches.
 * `code` is the first failure in spec order; `failures` lists every invariant that fails when R2..R7 are each
 * evaluated independently (R1 failure stops evaluation). Note: given R4 and R5, Σcount equals Σ blockPlan(n),
 * so a bytesFetched error always fails R6 first and R7 together; `failures` makes R7 observable.
 */
export function checkRandomBytesReplay(e: Incoming): ReplayResult {
  // R0 (O-69, cto-g1-spec errata E-1): for a randomBytes record, params.n must be a safe integer >= 1. Runs before R1, so
  // a forged n = 0 / negative / fractional / string record is reported as R0 whatever the rest of the record holds.
  if (isPlainObject(e) && typeof e === 'object' && e !== null && !Array.isArray(e) && field(e, 'kind') === 'randomBytes') {
    const params = field(e, 'params');
    const n = isPlainObject(params) && typeof params === 'object' && params !== null && !Array.isArray(params) && hasOwn(params, 'n') ? field(params, 'n') : undefined;
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
  const found: Array<[ReplayCode, string]> = [];

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
