// CTO int-v7 condition (1) on helper.loaded(), as accepted with conditions in CTO int-v8 ruling (1): the launcher-facing
// output of the real evidence helper for one fixed fixture (H, D, T frames and the preload's proof file), spawned with
// each tree's OWN helperSpawnArgs and helperSpawnEnv, is compared BYTE FOR BYTE with 9b7a1d8, except a closed,
// enumerated allowlist (ALLOW below; justification per entry in design v1.5 'int-v8 delta' (1)). Each allowlisted value
// is replaced by its "<ALLOW:id>" marker; the raw payload must first round-trip through JSON exactly (lossless), so the
// normalised record is the helper's own bytes with only those values swapped. Any other difference fails.
// No test-only deterministic entropy source exists on this head (check.mjs's LCG is synthetic, not wired to the
// helper), so (ii) does not apply and the D payload bytes and T.payload_sha256 are allowlisted (A2, A3).
// Usage (golden, recorded once from a 9b7a1d8 checkout, bare node, no preload in the parent):
//   node tools/ci/a25-2-launcher-shape.mjs --tree <checkout of 9b7a1d8> --out test/fixtures/a25-2-launcher-shape-9b7a1d8.json
// The test (r-g64-stream.test.mjs, 'CTO (1)') calls launcherShape(ROOT) and compares the bytes with that file.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const FIXTURE = Object.freeze({ run: 'golden', stream: 'golden-s0', rep: 'shuffle/adjacency-mod4/n-52', j: 0, calls: 40, token: 'grant-1@golden#0001' });
export const ALLOW = Object.freeze({
  A1: 'H.backstop.backstop_sha256 and proof.preload_sha256: the preload digest; the preload file differs per head by design',
  A2: 'D payload bytes: CSPRNG output, fresh on every run (only frame count and lengths are compared)',
  A3: 'T.payload_sha256: the sha256 of the A2 entropy',
  A4: 'proof.pid: the OS pid of the helper, different on every spawn; typed (CTO): integer > 1, not the parent pid, equal to the spawned child pid',
  A5: 'proof.manifest_sha256: the digest of the manifest over this tree; typed (CTO): 64 lowercase hex, equal to an independent recompute',
  A6: 'proof.sigusr1_disabled: absent at 9b7a1d8; int-v8 adds it and it must be exactly true (removed only when true)',
  A8: 'T.a25.gate_calls and T.a25.walks: the gate/walk count follows the rejection-sampling draws of the A2 entropy, so it differs per run (found in slot 1: two goldens 2839 vs 2854); typed (CTO-approved 2026-11-26, not final until the Sec code read at the committed head): keys exactly {gate_calls, walks}, integers, equal to each other, >= calls; the raw value is kept in the audit record (CTO A8 (3)), never discarded',
  A7: 'spawn argv: int-v8 adds --disable-sigusr1 (taken from each tree\'s own helperSpawnArgs; not part of the output)',
});
// CTO int-v8 r2 (1): A4/A5 are typed, constrained substitutions, not wildcards. A value that fails its check is
// swapped for <REJECT:id>, never <ALLOW:id>, so the byte compare fails.
export function checkA4(pid, childPid, parentPid) { return Number.isInteger(pid) && pid > 1 && pid !== parentPid && pid === childPid; }
export function checkA8(a25, calls) { return !!a25 && typeof a25 === 'object' && Object.keys(a25).join() === 'gate_calls,walks' && Number.isInteger(a25.gate_calls) && a25.walks === a25.gate_calls && a25.gate_calls >= calls; }
export function checkA5(v, recomputed) { return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && v === recomputed; }
// Independent of the tree's own a25-manifest.mjs: the manifest format (version 1, root, sorted entries, indent 1, '\n')
// rebuilt here with node:crypto; it must also equal the sha256 of the manifest bytes the helper was given.
export function independentManifestSha(root, relpaths, manifestBytes) {
  const h = (b) => createHash('sha256').update(b).digest('hex');
  const entries = {};
  for (const p of [...new Set(relpaths)].sort()) entries[p] = h(readFileSync(join(root, p)));
  const bytes = JSON.stringify({ version: 1, root, entries }, null, 1) + '\n';
  const a = h(bytes);
  return a === h(manifestBytes) ? a : null;
}
const exact = (raw, what) => { const o = JSON.parse(raw); if (JSON.stringify(o) !== raw) throw new Error(`launcherShape: ${what} does not round-trip byte-exactly`); return o; };
const walk = (d) => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });

// audit (optional object, CTO A8 (3) and harness fix (a)): filled with the raw values each substitution replaced
// (audit.raw) and the proof views (audit.proof_views), so the run record keeps them next to the golden compare.
export async function launcherShape(tree, baseEnv = process.env, audit = null) {
  const root = resolve(tree);
  const { buildManifest } = await import(pathToFileURL(join(root, 'tools/ci/a25-manifest.mjs')).href);
  const { helperSpawnArgs, helperSpawnEnv } = await import(pathToFileURL(join(root, 'verification/harness/stream-launcher.mjs')).href);
  const { FRAME, FrameReader } = await import(pathToFileURL(join(root, 'verification/harness/stream-frames.mjs')).href);
  const d = mkdtempSync(join(tmpdir(), 'a25-shape-'));
  try {
    const rel = ['src', 'verification', 'tools/ci'].flatMap((x) => walk(join(root, x))).map((f) => f.slice(root.length + 1));
    const { bytes, sha256 } = buildManifest(root, rel);
    const manifestPath = join(d, 'helper-manifest.json');
    writeFileSync(manifestPath, bytes);
    const e = { ...baseEnv }; delete e.NODE_OPTIONS;
    for (const k of Object.keys(e)) if (k.startsWith('ENTROPY_BACKSTOP') || k.startsWith('NODE_TEST')) delete e[k];
    const env = helperSpawnEnv(e, { token: FIXTURE.token, manifestPath, manifestSha256: sha256 });
    const proofPath = join(d, 'proof.json');
    env.ENTROPY_BACKSTOP_PROOF_FILE = proofPath;
    const F = FIXTURE;
    const args = helperSpawnArgs({ run_id: F.run }, { id: F.stream, rep: F.rep }, F.j, F.calls);
    // Async spawn: under a preloaded parent the G-39 hook replaces ENTROPY_BACKSTOP_PROOF_FILE with its own path and
    // records the proof per child object; the launcher reads it the same way (grantView.proof -> childProof). Bare,
    // the proof file above is read. Both give the same fields in the same order (pid, preload_sha256, token,
    // manifest_sha256[, sigusr1_disabled]); childProof's added mtime_ms is not output and is dropped.
    const r = await new Promise((ok, no) => {
      const c = spawn(process.execPath, args, { cwd: root, env, stdio: ['ignore', 'ignore', 'pipe', 'pipe'] });
      const fd3 = [], err = [];
      c.stdio[3].on('data', (b) => fd3.push(b)); c.stderr.on('data', (b) => err.push(b));
      const t = setTimeout(() => c.kill('SIGKILL'), 60000);
      c.once('error', no);
      c.once('close', (status, signal) => { clearTimeout(t); ok({ child: c, pid: c.pid, status, signal, stderr: Buffer.concat(err), output: [null, null, null, Buffer.concat(fd3)] }); });
    });
    if (r.status !== 0) throw new Error(`launcherShape: helper exit ${r.status} ${r.signal ?? ''}: ${String(r.stderr)}`);
    // The tree's own FrameReader validates the stream (it parses H/T to JSON, so the raw bytes are split here by the
    // documented layout [type u8][length u32 LE][payload] to keep the helper's exact payload bytes).
    const rd = new FrameReader(); const parsed = rd.push(r.output[3]); rd.end();
    const raw = r.output[3], frames = [];
    let o = 0;
    while (o < raw.length) { const type = raw[o], len = raw.readUInt32LE(o + 1); frames.push({ type, payload: raw.subarray(o + 5, o + 5 + len) }); o += 5 + len; }
    // Harness fix (b), CTO A8 (4): the raw split must agree with the validated FrameReader frames exactly (same count,
    // types, D bytes and H/T JSON) and consume the stream to its last byte.
    const splitOk = o === raw.length && frames.length === parsed.length && frames.every((f, i) => f.type === parsed[i].type
      && (f.type === FRAME.D ? Buffer.compare(f.payload, parsed[i].payload) === 0 : JSON.stringify(JSON.parse(Buffer.from(f.payload).toString('utf8'))) === JSON.stringify(parsed[i].json)));
    if (!splitOk) throw new Error(`FRAME-SPLIT: raw split (${frames.length} frames, ${o}/${raw.length} bytes) disagrees with FrameReader (${parsed.length} frames)`);
    const H = frames.filter((f) => f.type === FRAME.H), T = frames.filter((f) => f.type === FRAME.T), D = frames.filter((f) => f.type === FRAME.D);
    if (H.length !== 1 || T.length !== 1) throw new Error('launcherShape: not exactly one H and one T frame');
    const h = exact(Buffer.from(H[0].payload).toString('utf8'), 'H'), t = exact(Buffer.from(T[0].payload).toString('utf8'), 'T');
    const ev = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')]?.evidence ?? null;
    let pr;
    if (ev) {
      const p = ev.childProof(r.child);
      if (!p || typeof p !== 'object' || p.invalid) throw new Error(`launcherShape: no valid hook-recorded proof (${JSON.stringify(p)})`);
      pr = { ...p }; delete pr.mtime_ms;
      if (pr.sigusr1_disabled === null) delete pr.sigusr1_disabled; // childProof's null = field absent in the file
      // Harness fix (a), CTO A8 (4): the preloaded view (childProof) must be field-equal, in order, to the bare view of the
      // same file (the hook's proof file, <tmpdir>/ebs-proof-*/<this pid>-<seq>, matched by childProof's mtime_ms).
      const file = readdirSync(tmpdir()).filter((n) => n.startsWith('ebs-proof-')).flatMap((n) => { try { return readdirSync(join(tmpdir(), n)).filter((f) => f.startsWith(`${process.pid}-`)).map((f) => join(tmpdir(), n, f)); } catch { return []; } })
        .filter((f) => statSync(f).mtimeMs === p.mtime_ms);
      if (file.length !== 1) throw new Error(`PROOF-VIEWS-EQUAL: ${file.length} hook proof files match childProof's mtime_ms`);
      const bare = exact(readFileSync(file[0], 'utf8'), 'proof');
      if (JSON.stringify(bare) !== JSON.stringify(pr)) throw new Error(`PROOF-VIEWS-EQUAL: preloaded ${JSON.stringify(pr)} != bare ${JSON.stringify(bare)}`);
      if (audit) audit.proof_views = { mode: 'preloaded', equal: true, fields: Object.keys(pr) };
    } else {
      pr = exact(readFileSync(proofPath, 'utf8'), 'proof');
      if (audit) audit.proof_views = { mode: 'bare', equal: null, fields: Object.keys(pr) };
    }
    if (audit) audit.raw = { a25: 'a25' in t ? t.a25 : null, payload_sha256: t.payload_sha256 ?? null, backstop_sha256: h.backstop?.backstop_sha256 ?? null,
      pid: pr.pid ?? null, child_pid: r.pid, preload_sha256: pr.preload_sha256 ?? null, manifest_sha256: pr.manifest_sha256 ?? null };
    if (h.backstop && typeof h.backstop === 'object' && 'backstop_sha256' in h.backstop) h.backstop.backstop_sha256 = '<ALLOW:A1>';
    if ('payload_sha256' in t) t.payload_sha256 = '<ALLOW:A3>';
    if ('a25' in t) t.a25 = checkA8(t.a25, FIXTURE.calls) ? { gate_calls: '<ALLOW:A8>', walks: '<ALLOW:A8>' } : '<REJECT:A8>';
    if ('pid' in pr) pr.pid = checkA4(pr.pid, r.pid, process.pid) ? '<ALLOW:A4>' : '<REJECT:A4>';
    if ('preload_sha256' in pr) pr.preload_sha256 = '<ALLOW:A1>';
    if ('manifest_sha256' in pr) pr.manifest_sha256 = checkA5(pr.manifest_sha256, independentManifestSha(root, rel, bytes)) ? '<ALLOW:A5>' : '<REJECT:A5>';
    if (pr.sigusr1_disabled === true) delete pr.sigusr1_disabled; // A6: any other value stays and fails the compare
    const shape = { fixture: F, exit: r.status, frame_order: frames.map((f) => String.fromCharCode(f.type)).join(''),
      H: JSON.stringify(h), D: D.map((f) => f.payload.length), T: JSON.stringify(t), proof: JSON.stringify(pr) };
    return JSON.stringify(shape, null, 1) + '\n';
  } finally { rmSync(d, { recursive: true, force: true }); }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const at = (n) => { const i = process.argv.indexOf(`--${n}`); if (i < 0 || !process.argv[i + 1]) { process.stderr.write(`usage: --tree <dir> --out <file>\n`); process.exit(2); } return process.argv[i + 1]; };
  const out = at('out'), audit = {};
  writeFileSync(out, await launcherShape(at('tree'), process.env, audit), { flag: 'wx' });
  // CTO A8 (3): the substituted raw values go to the run record next to the golden (out + '.raw.json'), never discarded.
  writeFileSync(`${out}.raw.json`, JSON.stringify(audit, null, 1) + '\n', { flag: 'wx' });
  process.stdout.write(`wrote ${out} and ${out}.raw.json\n`);
}
