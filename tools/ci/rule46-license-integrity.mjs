#!/usr/bin/env node
// CI rule 46 (quality v5.5.5 CI 46; CPO-R101 LF-7, condition of LF-3 / CPO-R100 CA-1): LICENSE exact-sha integrity check.
// The claims lint skips LICENSE only because this check pins its bytes. Exit 0 only when the tracked file at the exact
// path 'LICENSE' hashes to the pinned unmodified Apache-2.0 text (sha256 cfc7749b…). Missing or changed bytes: exit 1.
// Usage: node tools/ci/rule46-license-integrity.mjs [--file PATH]   (default: the index blob of LICENSE, then the worktree)
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { licenseGuard, LICENSE_PATH, LICENSE_SHA256 } from '../license-guard.mjs';

const ROOT = new URL('../..', import.meta.url).pathname;

export function rule46(buf) {
  const g = licenseGuard(LICENSE_PATH, buf);
  return { ok: g.exempt && !g.red, sha256: g.sha256, detail: g.detail };
}

function readIndexOrWorktree() {
  try { return execFileSync('git', ['cat-file', 'blob', `:${LICENSE_PATH}`], { cwd: ROOT, stdio: ['ignore', 'pipe', 'ignore'] }); }
  catch { const p = join(ROOT, LICENSE_PATH); return existsSync(p) ? readFileSync(p) : null; }
}

function main() {
  const args = process.argv.slice(2);
  const i = args.indexOf('--file');
  const buf = i >= 0 ? (existsSync(args[i + 1]) ? readFileSync(args[i + 1]) : null) : readIndexOrWorktree();
  const worktree = existsSync(join(ROOT, LICENSE_PATH)) ? readFileSync(join(ROOT, LICENSE_PATH)) : null;
  const r = rule46(buf);
  const w = i >= 0 ? r : rule46(worktree);
  console.log(`rule46: ${r.ok && w.ok ? 'PASS' : 'FAIL'}: ${r.detail}${i >= 0 ? '' : `; worktree: ${w.detail}`} (pin ${LICENSE_SHA256.slice(0, 8)})`);
  process.exit(r.ok && w.ok ? 0 : 1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
