// G-64 (HoQ A9, MAJOR): the counting authority, outside the guarded process. It spawns the runner under the
// entropy-backstop preload with a launcher-created channel: a fresh 32-byte secret on the child's stdin (the
// backstop consumes it at preload, before runner code) and fd 3 for reports. Only lines whose HMAC verifies
// under that secret count, and only if the run exits 0. Anything a runner prints, writes to fd 3 without the
// secret, or produces in a process the launcher did not start, counts for nothing.
import { spawnSync } from 'node:child_process';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const BACKSTOP = fileURLToPath(new URL('../../tools/ci/entropy-backstop.mjs', import.meta.url));
export const macOf = (secret, o) => createHmac('sha256', secret).update(`${o.id}\n${o.n}\n${o.digest}\n${o.grant}`).digest('hex');

export function runCounted(runner, args = [], { cwd, timeout = 300_000 } = {}) {
  const secret = randomBytes(32);
  const env = { ...process.env, ENTROPY_BACKSTOP_CHANNEL: '1' };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, runner, ...args], { cwd, env, input: secret, stdio: ['pipe', 'pipe', 'pipe', 'pipe'], timeout, maxBuffer: 1 << 30 });
  const counted = [], rejected = [];
  for (const line of String(r.output[3] ?? '').split('\n')) {
    if (!line) continue;
    let o = null; try { o = JSON.parse(line); } catch { rejected.push('unparsable line'); continue; }
    const ok = o !== null && typeof o === 'object' && typeof o.mac === 'string' && /^[0-9a-f]{64}$/.test(o.mac)
      && timingSafeEqual(Buffer.from(o.mac, 'hex'), Buffer.from(macOf(secret, o), 'hex'));
    if (ok) counted.push({ id: o.id, n: o.n, digest: o.digest }); else rejected.push(`unauthenticated line for ${String(o && o.id)}`);
  }
  const stdout = String(r.stdout ?? ''), stderr = String(r.stderr ?? '');
  const hex = secret.toString('hex');
  return { status: r.status, counted: r.status === 0 ? counted : [], rejected, stdout, stderr, secretLeaked: stdout.includes(hex) || stderr.includes(hex) };
}
