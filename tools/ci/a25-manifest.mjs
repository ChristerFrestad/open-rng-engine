// A25-2 manifest (Backend). Pure helpers: no backstop import, no CSPRNG use. Design: verification/a25-2-design-v1.md.
import { createHash } from 'node:crypto';
import { readFileSync, writeSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXIT_A25_MANIFEST_OUTSIDE = 89; // a loaded module is not in the manifest
export const EXIT_A25_MANIFEST_DIGEST = 90;  // a module's bytes, or the manifest file itself, differ from the bound digest
export const MANIFEST_ENV = 'ENTROPY_BACKSTOP_MANIFEST';
// The manifest sha256 reaches the preload ONLY inside the grant (ENTROPY_BACKSTOP_GRANT = '<token>|m=<sha256>'),
// never as a standalone env var (CTO 21:29; split note Addendum C). Any other env name offering a sha is ignored.
export const GRANT_MANIFEST_SEP = '|m=';
const SHA_RE = /^[0-9a-f]{64}$/;

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

// Split '<token>|m=<sha256>'. Returns { token, sha256 } or null (missing or malformed m= part).
export function parseGrant(raw) {
  if (typeof raw !== 'string') return null;
  const i = raw.lastIndexOf(GRANT_MANIFEST_SEP);
  if (i <= 0) return null;
  const token = raw.slice(0, i), sha256 = raw.slice(i + GRANT_MANIFEST_SEP.length);
  if (token.includes('|') || !SHA_RE.test(sha256)) return null;
  return { token, sha256 };
}

// The preload's header check: read the located manifest, check its exact bytes against the grant-bound sha.
// Returns a frozen view { root, entries: Map }. On any failure: one stderr line, then exit 90 (before main).
export function readManifest(path, expectedSha256, exit = (c) => process.exit(c)) {
  const fail = (why) => {
    try { writeSync(2, `entropy-backstop[A25]: manifest ${why} (exit ${EXIT_A25_MANIFEST_DIGEST})\n`); } catch { /* stderr closed */ }
    exit(EXIT_A25_MANIFEST_DIGEST);
    throw new Error(`readManifest: ${why}`); // only reached when a test passes a non-exiting exit
  };
  if (typeof path !== 'string' || !isAbsolute(path)) return fail('locator missing or not absolute');
  if (typeof expectedSha256 !== 'string' || !SHA_RE.test(expectedSha256)) return fail('no grant-bound digest');
  let bytes;
  try { bytes = readFileSync(path); } catch { return fail(`unreadable: ${path}`); }
  const r = parseManifest(bytes, expectedSha256);
  if (!r.ok) return fail(r.why);
  return Object.freeze({ root: r.root, entries: r.entries });
}
