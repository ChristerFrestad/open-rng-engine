// G-64 (HoQ A9, MAJOR; A11: /proc/self/mem). The counting authority is THIS process (the launcher, the parent),
// and it holds no secret at all, so there is nothing a guarded runner can read from its own memory, receive or
// hold that makes a count. K3a's design (a 32-byte HMAC key handed to the child's backstop) failed because the
// key lived in the runner's own address space: HoQ A11 recovered it from /proc/self/mem and 3 forged lines
// were counted. Rule kept here: nothing the child can compute is a credential.
//
// What counts is what the launcher itself holds and checks, never what the child claims:
//   1. readiness: the launcher runs assertEvidenceRunReady on its own tree before it spawns anything;
//   2. the runner runs under the entropy-backstop preload with ENTROPY_BACKSTOP_CHANNEL=1 and fd 3 as the channel
//      (stdin is closed; no key is sent);
//   3. every fd-3 line must carry the FULL result (id, n, records). The launcher decodes the records, takes the
//      K entry for that id from ITS OWN K list (verification/k-tests-v1.1.json, or the kTests its caller
//      passes), re-runs the collector checks (n = number of records, every record one public-call outcome of
//      that primitive, the n floor), and computes the sha256 content digest itself. A claimed n, digest, grant
//      or MAC in a line is ignored;
//   4. a content digest counts once; nothing counts unless the run exits 0;
//   5. counted results are registered here (launcherCounted); the wave-1 statistic accepts nothing else.
// The child-side stamp/grant (G-54/G-65) stays as honest-path hygiene inside the runner; it is not authority.
//
// Named residual (R-G64-SRC, recorded in verification/harness/README.md): the launcher verifies what it
// received, not where the runner got it. A runner can deliver fabricated records of the right shape, exactly
// as it always could by handing collectCounted a fabricated call. Binding records to the engine's public calls
// needs the trusted side to make those calls (parent or helper process) once the engine exists (src is stubs).
// Scale residual (R-G64-SCALE): records travel through spawnSync's 1 GiB buffer; a 10^9-outcome run needs a
// streaming channel with incremental checks before any counted run.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertEvidenceRunReady } from './evidence-entry.mjs';
import { checkCollected, windowWidth } from './collector.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');

// Same canonical form as the backstop's resultContentDigest (BigInt v written as `${v}n`).
export function contentDigest(result) {
  const canon = JSON.stringify([result.id ?? null, result.n ?? null, result.records ?? null], (k, v) => (typeof v === 'bigint' ? `${v}n` : v));
  return createHash('sha256').update(canon).digest('hex');
}
const decode = (v) => (typeof v === 'string' && /^-?[0-9]+n$/.test(v) ? BigInt(v.slice(0, -1)) : Array.isArray(v) ? v.map(decode) : v);

const HELD = new WeakMap(); // counted result -> content digest, private to the launcher
export function launcherCounted(result) {
  const d = result !== null && typeof result === 'object' ? HELD.get(result) : undefined;
  return d !== undefined && contentDigest(result) === d;
}

function lineResult(o, byId, floor, seen) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return { why: 'not an object' };
  const kTest = byId.get(o.id);
  if (!kTest) return { why: 'id is not an entry of the launcher\'s K list' };
  if (!Array.isArray(o.records)) return { why: 'no records: a count is only what the launcher itself holds and checks' };
  const result = { id: o.id, n: o.n, records: decode(o.records) };
  const f = checkCollected(result, kTest, Number.isSafeInteger(result.n) ? result.n * windowWidth(kTest) : NaN, { floor, grant: false });
  if (f.length) return { why: f.join('; ') };
  const digest = contentDigest(result);
  if (seen.has(digest)) return { why: 'duplicate content digest (counted once)' };
  seen.add(digest);
  return { result, digest };
}

export function runCounted(runner, args = [], { cwd, timeout = 300_000, kTests, floor = true } = {}) {
  assertEvidenceRunReady(ROOT);
  const ks = kTests ?? JSON.parse(readFileSync(join(ROOT, 'verification/k-tests-v1.1.json'), 'utf8')).tests;
  const byId = new Map(ks.map((k) => [k.id, k]));
  const env = { ...process.env, ENTROPY_BACKSTOP_CHANNEL: '1' };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, runner, ...args], { cwd, env, stdio: ['ignore', 'pipe', 'pipe', 'pipe'], timeout, maxBuffer: 1 << 30 });
  const counted = [], rejected = [], seen = new Set();
  for (const line of String(r.output?.[3] ?? '').split('\n')) {
    if (!line) continue;
    let o = null; try { o = JSON.parse(line); } catch { rejected.push('unparsable line'); continue; }
    const x = lineResult(o, byId, floor, seen);
    if (x.why) { rejected.push(`${String(o && o.id)}: ${x.why}`); continue; }
    x.result.digest = x.digest; // outside the digested fields (id, n, records)
    counted.push(x.result);
  }
  if (r.status === 0) for (const res of counted) HELD.set(res, res.digest);
  const stdout = String(r.stdout ?? ''), stderr = String(r.stderr ?? '');
  return { status: r.status, counted: r.status === 0 ? counted : [], rejected, stdout, stderr };
}
