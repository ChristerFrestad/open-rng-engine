#!/usr/bin/env node
// DOD-PH0-QIU05 check: 0 Norway-targeting factors in project materials (PLAN QIU-05, frame §3.3).
// Factor classes (regulator-listed, frame §3.3): F1 tie to the country, F2 local language,
// F3 local currency, F4 local marketing/support contact. Zero dependencies. Terms are \u-escaped.
// The ONLY allowed mention is the exact no-targeting sentence below (DECISIONS P2), in README.md.
// Scope: every git-tracked file except this checker and LICENSE, which is skipped only by exact path + pinned sha256
// (tools/license-guard.mjs); altered LICENSE bytes are scanned and reported red.
// Usage: node tools/qiu05-check.mjs | node tools/qiu05-check.mjs --expect-red FILE
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { licenseGuard, LICENSE_PATH } from './license-guard.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
export const ALLOWED = {
  file: 'README.md',
  sentence: 'This project is not intended for, aimed at, or marketed to Norway, or any market where the integrator lacks a licence.',
};
const RULES = [
  ['F1-tie', /\b(?:\u006eorway|\u006eorwegian|\u006eorge|\u006eoreg|\u006eorsk\w*|\u006fslo|\u0062ergen|\u0074rondheim|\u0073tavanger)\b/gi],
  ['F1-tie-domain', /\b[\w-]+\.no\b(?![\w-])/gi],
  ['F2-language-chars', /[\u00e6\u00f8\u00e5\u00c6\u00d8\u00c5]/g],
  ['F2-language-words', /\b(?:\u0069kke|\u006fgs\u00e5|\u0070engespill|\u0073pill|\u0068vordan|\u0062okm\u00e5l|\u006eynorsk|\u0076ennligst|\u0074akk|\u0068jelp|\u006bundeservice|\u0067evinst|\u0069nnsats|\u006cykke)\b/gi],
  ['F3-currency', /\b\u004eOK\b|\b\u006br\b|\b\u006broner\b|\b\u006brone\b/g],
  ['F4-support', /\+47[\s\d]{6,}/g],
];

function check(name, text) {
  const hits = [];
  text.split('\n').forEach((line0, i) => {
    let line = line0;
    if (name === ALLOWED.file) line = line.split(ALLOWED.sentence).join(' ');
    for (const [id, re] of RULES) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) hits.push(`${name}:${i + 1}: ${id}: "${m[0]}"`);
    }
  });
  return hits;
}

// Known-bad fixture: one string per factor class, \u-escaped here and materialised only in scratch.
const KNOWN_BAD = '# known-bad fixture\n\nPris: 99 \u004e\u004f\u004b. \u004e\u006f\u0072\u0073\u006b \u006b\u0075\u006e\u0064\u0065\u0073\u0065\u0072\u0076\u0069\u0063\u0065: support@example.\u006e\u006f +\u0034\u0037 00 00 00 00\n';

const args = process.argv.slice(2);
if (args[0] === '--self-test') {
  const dir = mkdtempSync(join(tmpdir(), 'qiu05-fixture-'));
  const f = join(dir, 'README.md');
  writeFileSync(f, KNOWN_BAD);
  const hits = check('scratch:README.md', readFileSync(f, 'utf8'));
  rmSync(dir, { recursive: true, force: true });
  hits.forEach((h) => console.log(h));
  const classes = new Set(hits.map((h) => h.split(': ')[1].split('-')[0]));
  if (!['F1', 'F2', 'F3', 'F4'].every((c) => classes.has(c))) { console.error('qiu05: known-bad fixture did NOT hit all four factor classes (FAIL)'); process.exit(1); }
  console.log(`qiu05: scratch known-bad fixture turned red with ${hits.length} hit(s) across F1-F4 (expected, PASS); scratch removed`);
  process.exit(0);
}
if (args[0] === '--expect-red') {
  const hits = check(args[1], readFileSync(args[1], 'utf8'));
  hits.forEach((h) => console.log(h));
  if (!hits.length) { console.error(`qiu05: known-bad fixture ${args[1]} did NOT turn red (FAIL)`); process.exit(1); }
  console.log(`qiu05: known-bad fixture turned red with ${hits.length} hit(s) (expected, PASS)`);
  process.exit(0);
}
if (args[0] === '--check-license') {
  const g = licenseGuard(LICENSE_PATH, readFileSync(args[1]));
  console.log(`qiu05: ${g.detail}`);
  process.exit(g.red ? 1 : 0);
}
const lic = licenseGuard(LICENSE_PATH, (() => { try { return readFileSync(join(ROOT, LICENSE_PATH)); } catch { return null; } })());
const files = execFileSync('git', ['ls-files', '--cached'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter(Boolean)
  .filter((f) => f !== 'tools/qiu05-check.mjs' && !(f === LICENSE_PATH && lic.exempt));
const hits = files.flatMap((f) => check(f, readFileSync(join(ROOT, f), 'utf8')));
if (lic.red) hits.push(`LICENSE: ${lic.detail}`);
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
const stance = readme.includes(ALLOWED.sentence);
hits.forEach((h) => console.log(h));
console.log(`qiu05: ${files.length} tracked file(s) scanned (LICENSE ${lic.exempt ? 'excluded: exact path + sha ' + lic.sha256.slice(0, 8) : 'NOT excluded'}), ${hits.length} factor hit(s); P2 no-targeting sentence present in README: ${stance}`);
process.exit(hits.length || !stance ? 1 : 0);
