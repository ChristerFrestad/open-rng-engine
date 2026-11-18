// R-93 replay invariant checker for audited `randomBytes` evidence (PLAN R-93 L203, R-61 L169, R-56 L164;
// cto-g1-spec.md §5.2–§5.4; CPO-R98 / C-11, DECISIONS L77). VERIFICATION BUILD ONLY (src/verify/, rule 24).
// Pure function: never fetches, no I/O, no clock, no state. The context check (CONTEXT_MISMATCH, §3.11)
// runs before this in the full replay and is out of scope here.
// Order (first failure wins): R1 schema, R2 len(output)==n, R3 lowercase even-length hex, R4 reads vs blockPlan(n),
// R5 count===width per entry, R6 Σcount===bytesFetched, R7 bytesFetched===n+16·⌈n/65520⌉.
// R1 checks the §5.2 shape except the `output` hex pattern, which is reported as R3 so each invariant is observable.

import { blockCount, blockWidthAt, blockPlanTotal, isValidBlockPlanN } from '../entropy/blockPlan.ts';

export type ReplayCode = 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7';
export type ReplayResult = { ok: true } | { ok: false; code: ReplayCode; detail: string; failures: ReplayCode[] };

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAPPING_KINDS: ReadonlySet<string> = new Set(['randomInt', 'shuffle', 'sample', 'weightedPick']);
const MAPPING_READ = /^(?:[0-9a-f]{8}|[0-9a-f]{14})$/;
const LOWER_HEX = /^[0-9a-f]*$/;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const has = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const isIntIn = (v: unknown, lo: number, hi: number): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= lo && v <= hi;

/** §5.2 reads/output shape for any kind (randomBytes branch and mapping branch). Hex pattern of `output` excluded (R3). */
export function validateReadsOutputSchema(e: unknown): string | null {
  if (!isObj(e)) return 'evidence is not an object';
  for (const k of ['kind', 'params', 'reads', 'bytesFetched']) if (!has(e, k)) return `missing ${k}`;
  const kind = e['kind'];
  if (kind !== 'randomBytes' && !(typeof kind === 'string' && MAPPING_KINDS.has(kind))) return 'unknown kind';
  if (!isObj(e['params'])) return 'params is not an object';
  if (!isIntIn(e['bytesFetched'], 0, MAX_SAFE)) return 'bytesFetched is not a safe non-negative integer';
  const reads = e['reads'];
  if (!Array.isArray(reads)) return 'reads is not an array';
  if (kind !== 'randomBytes') {
    if (has(e, 'output')) return 'output present on a mapping primitive';
    for (const r of reads) if (typeof r !== 'string' || !MAPPING_READ.test(r)) return 'mapping read is not 8 or 14 lowercase hex';
    return null;
  }
  const params = e['params'] as Record<string, unknown>;
  if (!has(params, 'n') || !isIntIn(params['n'], 0, MAX_SAFE)) return 'params.n is not a safe non-negative integer';
  if (!isValidBlockPlanN(params['n'])) return 'params.n must be >= 1 (PLAN L605: n = 0 throws RANGE_INVALID, no evidence)';
  if (!has(e, 'output')) return 'missing output';
  if (typeof e['output'] !== 'string') return 'output is not a string';
  for (let i = 0; i < reads.length; i++) {
    const r: unknown = reads[i];
    if (!isObj(r)) return `reads[${i}] is not an object`;
    const keys = Object.keys(r);
    if (keys.length !== 2 || !has(r, 'width') || !has(r, 'count')) return `reads[${i}] must be exactly {width, count}`;
    if (!isIntIn(r['width'], 17, 65536)) return `reads[${i}].width not an integer in 17..65536`;
    if (!isIntIn(r['count'], 17, 65536)) return `reads[${i}].count not an integer in 17..65536`;
  }
  return null;
}

/**
 * R-93 replay invariants R1..R7 for kind = randomBytes. Never fetches.
 * `code` is the first failure in spec order; `failures` lists every invariant that fails when R2..R7 are each
 * evaluated independently (R1 failure stops evaluation). Note: given R4 and R5, Σcount equals Σ blockPlan(n),
 * so a bytesFetched error always fails R6 first and R7 together; `failures` makes R7 observable.
 */
export function checkRandomBytesReplay(e: unknown): ReplayResult {
  const schemaErr = validateReadsOutputSchema(e);
  if (schemaErr !== null) return { ok: false, code: 'R1', detail: schemaErr, failures: ['R1'] };
  const ev = e as Record<string, unknown>;
  if (ev['kind'] !== 'randomBytes') return { ok: false, code: 'R1', detail: 'kind is not randomBytes', failures: ['R1'] };
  const n = (ev['params'] as Record<string, unknown>)['n'] as number;
  const output = ev['output'] as string;
  const reads = ev['reads'] as ReadonlyArray<{ width: number; count: number }>;
  const bytesFetched = ev['bytesFetched'] as number;
  const found: Array<[ReplayCode, string]> = [];

  if (output.length !== 2 * n) found.push(['R2', `output has ${output.length} hex chars, expected 2n = ${2 * n}`]);
  if (output.length % 2 !== 0 || !LOWER_HEX.test(output)) found.push(['R3', 'output is not lowercase even-length hex (no prefix, no separators)']);

  const blocks = blockCount(n);
  if (reads.length !== blocks) {
    found.push(['R4', `reads.length ${reads.length} !== blockPlan(n).length ${blocks}`]);
  } else {
    for (let i = 0; i < blocks; i++) {
      const w = blockWidthAt(n, i);
      if (reads[i]!.width !== w) { found.push(['R4', `reads[${i}].width ${reads[i]!.width} !== blockPlan(n)[${i}] ${w}`]); break; }
    }
  }
  let sum = 0;
  let r5 = false;
  for (let i = 0; i < reads.length; i++) {
    if (!r5 && reads[i]!.count !== reads[i]!.width) { found.push(['R5', `reads[${i}].count ${reads[i]!.count} !== width ${reads[i]!.width}`]); r5 = true; }
    sum += reads[i]!.count;
  }
  if (sum !== bytesFetched) found.push(['R6', `Σcount ${sum} !== bytesFetched ${bytesFetched}`]);
  const total = blockPlanTotal(n);
  if (bytesFetched !== total) found.push(['R7', `bytesFetched ${bytesFetched} !== n + 16·⌈n/65520⌉ = ${total}`]);

  if (found.length === 0) return { ok: true };
  const [code, detail] = found[0]!;
  return { ok: false, code, detail, failures: found.map(([c]) => c) };
}
