// A25-2 manifest (Backend). Pure helpers: no backstop import, no CSPRNG use. Design: verification/a25-2-design-v1.md.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXIT_A25_MANIFEST_OUTSIDE = 89; // a loaded module is not in the manifest
export const EXIT_A25_MANIFEST_DIGEST = 90;  // a module's bytes, or the manifest file itself, differ from the bound digest
export const MANIFEST_ENV = 'ENTROPY_BACKSTOP_MANIFEST';
export const MANIFEST_SHA_ENV = 'ENTROPY_BACKSTOP_MANIFEST_SHA256';

const sha = (b) => createHash('sha256').update(b).digest('hex');
const posix = (p) => p.split(sep).join('/');

function relOf(root, abs) {
  const r = relative(root, abs);
  if (r === '' || r.startsWith('..') || isAbsolute(r)) return null;
  return posix(r);
}

// relpaths: the helper's traced module closure, relative to root. Returns { manifest, bytes, sha256 }.
export function buildManifest(root, relpaths) {
  if (typeof root !== 'string' || !isAbsolute(root)) throw new TypeError('buildManifest: root must be an absolute path');
  if (!Array.isArray(relpaths) || relpaths.length === 0) throw new TypeError('buildManifest: relpaths must be a non-empty array');
  const entries = {};
  for (const p of [...new Set(relpaths)].sort()) {
    const abs = resolve(root, p);
    const rel = relOf(root, abs);
    if (rel === null || rel !== p) throw new Error(`buildManifest: ${p} is not a normalised path under root`);
    entries[rel] = sha(readFileSync(abs));
  }
  const manifest = { version: 1, root: resolve(root), entries };
  const bytes = JSON.stringify(manifest, null, 1) + '\n';
  return { manifest, bytes, sha256: sha(bytes) };
}

// Parse manifest bytes already checked against the bound digest. Returns a frozen view.
export function parseManifest(bytes, expectedSha) {
  if (typeof expectedSha !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSha)) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'no bound manifest digest' };
  if (sha(bytes) !== expectedSha) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'manifest file digest differs from the bound digest' };
  let m;
  try { m = JSON.parse(Buffer.isBuffer(bytes) ? bytes.toString('utf8') : bytes); } catch { return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'manifest is not JSON' }; }
  if (!m || m.version !== 1 || typeof m.root !== 'string' || !isAbsolute(m.root) || !m.entries || typeof m.entries !== 'object') return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'manifest shape' };
  const entries = new Map();
  for (const [k, v] of Object.entries(m.entries)) {
    if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: `bad digest for ${k}` };
    entries.set(k, v);
  }
  return { ok: true, root: m.root, entries };
}

// Check one load. Returns { ok:true, bytes } (the exact hashed bytes, to pass on) or { ok:false, code, why }.
export function verifyLoad(view, url, readBytes = (p) => readFileSync(p)) {
  if (typeof url !== 'string' || !url.startsWith('file:')) return { ok: false, code: EXIT_A25_MANIFEST_OUTSIDE, why: `not a file URL: ${url}` };
  let abs;
  try { abs = fileURLToPath(url); } catch { return { ok: false, code: EXIT_A25_MANIFEST_OUTSIDE, why: `bad file URL: ${url}` }; }
  const rel = relOf(view.root, abs);
  if (rel === null || !view.entries.has(rel)) return { ok: false, code: EXIT_A25_MANIFEST_OUTSIDE, why: `not in manifest: ${url}` };
  let bytes;
  try { bytes = readBytes(abs); } catch { return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: `unreadable: ${rel}` }; }
  if (sha(bytes) !== view.entries.get(rel)) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: `digest differs: ${rel}` };
  return { ok: true, bytes, rel };
}

// One-argument predicate for installLockdown: exactly true for manifest file URLs and allowlisted builtins.
export function makeIsManifestUrl(view, builtins = []) {
  const allow = new Set(builtins);
  return function isManifestUrl(url) {
    if (typeof url !== 'string') return false;
    if (url.startsWith('node:')) return allow.has(url);
    if (!url.startsWith('file:')) return false;
    let abs; try { abs = fileURLToPath(url); } catch { return false; }
    const rel = relOf(view.root, abs);
    return rel !== null && view.entries.has(rel);
  };
}
