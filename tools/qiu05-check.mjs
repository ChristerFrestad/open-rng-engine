#!/usr/bin/env node
// DOD-PH0-QIU05 check: 0 Norway-targeting factors in project materials (PLAN QIU-05, frame §3.3).
// Factor classes (regulator-listed, frame §3.3): F1 tie to Norway, F2 Norwegian language,
// F3 NOK currency, F4 Norwegian marketing/support contact. Zero dependencies.
// The ONLY allowed mention is the exact no-targeting sentence below (DECISIONS P2), in README.md.
// Scope: every git-tracked file except this checker and tools/fixtures/**.
// Usage: node tools/qiu05-check.mjs | node tools/qiu05-check.mjs --expect-red FILE
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
export const ALLOWED = {
  file: 'README.md',
  sentence: 'This project is not intended for, aimed at, or marketed to Norway, or any market where the integrator lacks a licence.',
};
const RULES = [
  ['F1-tie', /\b(?:norway|norwegian|norge|noreg|norsk\w*|oslo|bergen|trondheim|stavanger)\b/gi],
  ['F1-tie-domain', /\b[\w-]+\.no\b(?![\w-])/gi],
  ['F2-language-chars', /[æøåÆØÅ]/g],
  ['F2-language-words', /\b(?:ikke|også|pengespill|spill|hvordan|bokmål|nynorsk|vennligst|takk|hjelp|kundeservice|gevinst|innsats|lykke)\b/gi],
  ['F3-currency', /\bNOK\b|\bkr\b|\bkroner\b|\bkrone\b/g],
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

const args = process.argv.slice(2);
if (args[0] === '--expect-red') {
  const hits = check(args[1], readFileSync(args[1], 'utf8'));
  hits.forEach((h) => console.log(h));
  if (!hits.length) { console.error(`qiu05: known-bad fixture ${args[1]} did NOT turn red (FAIL)`); process.exit(1); }
  console.log(`qiu05: known-bad fixture turned red with ${hits.length} hit(s) (expected, PASS)`);
  process.exit(0);
}
const files = execFileSync('git', ['ls-files', '--cached'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter(Boolean)
  .filter((f) => f !== 'tools/qiu05-check.mjs' && !f.startsWith('tools/fixtures/') && f !== 'LICENSE');
const hits = files.flatMap((f) => check(f, readFileSync(join(ROOT, f), 'utf8')));
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
const stance = readme.includes(ALLOWED.sentence);
hits.forEach((h) => console.log(h));
console.log(`qiu05: ${files.length} tracked file(s) scanned (LICENSE excluded: unmodified Apache-2.0 text), ${hits.length} factor hit(s); P2 no-targeting sentence present in README: ${stance}`);
process.exit(hits.length || !stance ? 1 : 0);
