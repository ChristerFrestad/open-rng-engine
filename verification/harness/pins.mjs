// Evidence-harness pins. Decision rule v1 (FROZEN, verification/decision-rule-v1.md, sha256 5d09c75a...).
// Rule 15 (TODO-CTO-2): NIST STS 2.1.2 "driven by a fixed answer file. The answer-file bytes are frozen
// with the harness." TestU01 1.2.3 "through a pinned C driver over unif01_CreateExternGenBits ... The
// driver source is frozen with the harness." Rule 17(ii) R-PIN-1: the archive pin is the sha256 of the
// archive fetched from the official URL; a re-fetch with a different sha256 is a pin change (re-freeze).
// Node built-ins only. Every check returns a list of findings; an empty list is green.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const FROZEN_RULE_PATH = 'verification/decision-rule-v1.md';
export const FROZEN_RULE_SHA256 = '5d09c75a0fe9ab3679166d6705ba16f6d816f61b9924b2abec735cb45f2e022f';
export const TOOL_PINS_PATH = 'verification/tool-pins-v1.1.json';
export const TOOL_PINS_SHA256 = '605e9a9973d754b1211c3d2e6ebe5202c28ee3656c988fa0203a0d68da899f8b';

// Rule 15 archive pins (values copied from the frozen text; cross-checked against it below).
export const ARCHIVE_PINS = Object.freeze([
  Object.freeze({
    tool: 'NIST STS', version: '2.1.2', filename: 'sts-2_1_2.zip', byteSize: 43915127,
    url: 'https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip',
    sha256: '0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157',
  }),
  Object.freeze({
    tool: 'TestU01', version: '1.2.3', filename: 'TestU01-1.2.3.zip', byteSize: 3123035,
    url: 'https://simul.iro.umontreal.ca/testu01/TestU01-1.2.3.zip',
    sha256: 'bc1d1dd2aea7ed3b3d28eaad2c8ee55913f11ce67aec8fe4f643c1c0d2ed1cac',
  }),
]);

// Rule 15: harness-frozen bytes. sts-answers.txt answers the assess prompts of STS 2.1.2 src/utilities.c
// in call order (see verification/harness/README.md); tu01-driver.c is the TestU01 driver source.
export const HARNESS_FILE_PINS = Object.freeze({
  'verification/harness/sts-answers.txt': 'f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666383',
  'verification/harness/tu01-driver.c': '5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c88',
});

// Rule 4 / rule 15: "./assess 1000000"; m = 1,000 sequences; binary input. Exact answer-file text.
export const STS_ANSWERS_TEXT = '0\nraw-stream.bin\n1\n0\n1000\n1\n';

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const HEX64 = /^[0-9a-f]{64}$/;

export function checkHarnessPins(root) {
  const findings = [];
  for (const [rel, want] of Object.entries(HARNESS_FILE_PINS)) {
    if (!HEX64.test(want)) { findings.push(`pin for ${rel} is not a sha256 literal`); continue; }
    const p = join(root, rel);
    if (!existsSync(p)) { findings.push(`pinned harness file missing: ${rel}`); continue; }
    const got = sha256(readFileSync(p));
    if (got !== want) findings.push(`rule 15: ${rel} sha256 ${got} != pinned ${want}`);
  }
  const ans = join(root, 'verification/harness/sts-answers.txt');
  if (existsSync(ans) && readFileSync(ans, 'utf8') !== STS_ANSWERS_TEXT) {
    findings.push('rule 15: sts-answers.txt text differs from STS_ANSWERS_TEXT');
  }
  return findings;
}

// The archive pins must equal the frozen rule text and the frozen tool-pins file byte for byte.
export function checkArchivePinsAgainstFrozen(root) {
  const findings = [];
  const rulePath = join(root, FROZEN_RULE_PATH);
  if (!existsSync(rulePath)) return [`frozen rule missing: ${FROZEN_RULE_PATH}`];
  const ruleBytes = readFileSync(rulePath);
  if (sha256(ruleBytes) !== FROZEN_RULE_SHA256) findings.push('frozen rule sha256 changed');
  const rule = ruleBytes.toString('utf8');
  const pinsPath = join(root, TOOL_PINS_PATH);
  if (!existsSync(pinsPath)) return [...findings, `tool pins missing: ${TOOL_PINS_PATH}`];
  const pinsBytes = readFileSync(pinsPath);
  if (sha256(pinsBytes) !== TOOL_PINS_SHA256) findings.push('tool-pins-v1.1.json sha256 changed');
  const tools = JSON.parse(pinsBytes.toString('utf8')).tools;
  for (const a of ARCHIVE_PINS) {
    if (!HEX64.test(a.sha256)) { findings.push(`${a.tool}: pin is not a sha256 literal`); continue; }
    if (!rule.includes('`' + a.filename + '`, sha256 `' + a.sha256 + '`')) {
      findings.push(`rule 15: ${a.tool} pin ${a.filename} ${a.sha256} not in the frozen rule text`);
    }
    const t = tools.find((x) => x.filename === a.filename);
    if (!t) { findings.push(`${a.tool}: not in tool-pins-v1.1.json`); continue; }
    if (t.sha256 !== a.sha256 || t.url !== a.url || t.byte_size !== a.byteSize || t.version !== a.version) {
      findings.push(`${a.tool}: pin differs from tool-pins-v1.1.json`);
    }
  }
  return findings;
}

// Rule 17(ii): an archive on disk must match its pin before the harness builds from it.
export function checkArchiveFile(path, filename) {
  const a = ARCHIVE_PINS.find((x) => x.filename === filename);
  if (!a) return [`no pin for archive ${filename}`];
  if (!existsSync(path)) return [`archive missing: ${path}`];
  const b = readFileSync(path);
  const findings = [];
  if (b.length !== a.byteSize) findings.push(`${filename}: size ${b.length} != pinned ${a.byteSize}`);
  const got = sha256(b);
  if (got !== a.sha256) findings.push(`rule 17(ii): ${filename} sha256 ${got} != pinned ${a.sha256} (pin change: re-freeze)`);
  return findings;
}
