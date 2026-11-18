#!/usr/bin/env node
// Shared claims lint (PLAN R-16 / B10 / QIU-07 / RQ-FC-13). Zero dependencies.
// Scope (R-16): README*, package.json description + keywords, docs/**, release notes,
// SECURITY.md, and the intended GitHub repo description/topics recorded in REMOTE-PENDING.md
// between the CLAIMS-LINT-SCOPE markers.
// Usage:  node tools/claims-lint.mjs                 -> lint the repo scope, exit 1 on any hit
//         node tools/claims-lint.mjs --expect-red F  -> lint file F only, exit 0 only if it has >= 1 hit
// Strict reading pending G1 carry item C-9: certif/complian/align are unconditional, and FIPS is
// always a hit because the "exact allowed sentence" is not yet pinned.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const ANCHOR = String.raw`(?:GLI-11|GLI|NIST|UKGC|RTS|MGA|lab)`;
const COMPAR = String.raw`(?:exceed\w*|above|beyond|surpass\w*|meets)`;
const NEAR = String.raw`(?:\W+\w+){0,4}\W+`; // within 5 words
const RULES = [
  ['R16-certif', /\bcertif\w*/gi],
  ['R16-complian', /\bcomplian\w*/gi],
  ['R16-align', /\balign\w*/gi],
  ['R16-comparative', new RegExp(String.raw`\b${COMPAR}${NEAR}${ANCHOR}\b|\b${ANCHOR}${NEAR}${COMPAR}\b`, 'gi')],
  ['R16-nist-claim', /\bNIST[- ](?:certified|approved|compliant)\b/gi],
  ['R16-approved', /\bapproved\b/gi],
  ['R16-gold-standard', /\bgold\s+standard\b/gi],
  ['R16-fips', /\bFIPS\b/gi],
  ['R16-badge', /!\[[^\]]*(?:GLI|NIST)[^\]]*\]\([^)]*\)|!\[[^\]]*\]\([^)]*(?:GLI|NIST)[^)]*\)|<img\b[^>]*(?:GLI|NIST)[^>]*>/gi],
];

function lintText(name, text) {
  const hits = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    for (const [id, re] of RULES) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) hits.push(`${name}:${i + 1}: ${id}: "${m[0]}"`);
    }
  });
  return hits;
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function scopeTexts() {
  const out = [];
  for (const n of readdirSync(ROOT)) {
    if (/^(README|RELEASE-NOTES|CHANGELOG|SECURITY)[^/]*\.md$/i.test(n)) out.push([n, readFileSync(join(ROOT, n), 'utf8')]);
  }
  for (const p of walk(join(ROOT, 'docs'))) out.push([relative(ROOT, p), readFileSync(p, 'utf8')]);
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  out.push(['package.json#description', String(pkg.description ?? '')]);
  out.push(['package.json#keywords', (pkg.keywords ?? []).join('\n')]);
  const rp = join(ROOT, 'REMOTE-PENDING.md');
  if (existsSync(rp)) {
    const m = readFileSync(rp, 'utf8').match(/<!-- CLAIMS-LINT-SCOPE:BEGIN -->([\s\S]*?)<!-- CLAIMS-LINT-SCOPE:END -->/);
    if (!m) { console.error('claims-lint: REMOTE-PENDING.md has no CLAIMS-LINT-SCOPE block'); process.exit(2); }
    out.push(['REMOTE-PENDING.md#repo-description-and-topics', m[1]]);
  }
  return out;
}

const args = process.argv.slice(2);
if (args[0] === '--expect-red') {
  const f = args[1];
  const hits = lintText(f, readFileSync(f, 'utf8'));
  hits.forEach((h) => console.log(h));
  if (hits.length === 0) { console.error(`claims-lint: known-bad fixture ${f} did NOT turn red (FAIL)`); process.exit(1); }
  console.log(`claims-lint: known-bad fixture ${f} turned red with ${hits.length} hit(s) (expected, PASS)`);
  process.exit(0);
}
const texts = scopeTexts();
const hits = texts.flatMap(([n, t]) => lintText(n, t));
hits.forEach((h) => console.log(h));
console.log(`claims-lint: ${texts.length} scope item(s), ${hits.length} hit(s)`);
process.exit(hits.length ? 1 : 0);
