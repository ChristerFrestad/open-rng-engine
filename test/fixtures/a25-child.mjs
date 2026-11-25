// Shared child/hostile-tree helpers for test/r-g64-a25.test.mjs and test/r-g64-a25-bare.mjs (A25-3 / A25-4).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
export const MARK = "Symbol.for('open-rng-engine/entropy-backstop/v1')";
export const sha = (b) => createHash('sha256').update(b).digest('hex');

export function child(code, { root = ROOT, mode = 'a25', preload = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'a25-'));
  try {
    const f = join(dir, 'child.mjs');
    writeFileSync(f, `const SRC = ${JSON.stringify(pathToFileURL(join(root, 'src/index.ts')).href)};\nconst ROOTURL = ${JSON.stringify(pathToFileURL(root + '/').href)};\nconst M = () => globalThis[${MARK}].helper;\n${code}\n`);
    const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.ENTROPY_BACKSTOP_CHANNEL; delete env.ENTROPY_BACKSTOP_HELPER;
    if (mode !== null) env.ENTROPY_BACKSTOP_HELPER = mode;
    const args = preload ? ['--import', join(root, 'tools/ci/entropy-backstop.mjs'), f] : [f];
    const r = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 60000 });
    return { status: r.status, out: r.stdout, err: r.stderr };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
// A temp tree with src/ and the preload copied, and src files edited by `edit` ({ path: (text) => text }).
export function hostile(edit) {
  const root = mkdtempSync(join(tmpdir(), 'a25-src-'));
  cpSync(join(ROOT, 'src'), join(root, 'src'), { recursive: true });
  mkdirSync(join(root, 'tools/ci'), { recursive: true }); cpSync(BACKSTOP, join(root, 'tools/ci/entropy-backstop.mjs'));
  cpSync(join(ROOT, 'package.json'), join(root, 'package.json'));
  for (const [p, fn] of Object.entries(edit)) writeFileSync(join(root, p), fn(readFileSync(join(root, p), 'utf8')));
  return root;
}
export const withHostile = (edit, code) => { const root = hostile(edit); try { return child(code, { root }); } finally { rmSync(root, { recursive: true, force: true }); } };
export const FILL = 'src/entropy/index.ts';
export const fillBody = (body) => ({ [FILL]: (t) => { const n = t.replace(/export function fillBuffer\(target: Uint8Array\): Uint8Array \{[\s\S]*?\n\}/, `export function fillBuffer(target: Uint8Array): Uint8Array {\n${body}\n  return target;\n}`); assert.notEqual(n, t, 'fillBuffer not found'); return n; } });
// True when this process runs without the preload (the hostile-tree cases need that).
export const isBare = () => globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')] === undefined;
