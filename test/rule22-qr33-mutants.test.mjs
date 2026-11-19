// QR-33 matcher mutants (HoQ b15a2ff5 gaps 1-2 and the HoQ matcher clarification; CTO batch E). Each mutant
// is a copy of tools/ci/rule22-exports-map.mjs with one rule changed; its --self-test must fail, naming the
// fixture that kills it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { qr33Hit, qr33RunRed, qr33RunGreen, QR33_BOUNDARY_GREEN } from '../tools/ci/rule22-exports-map.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const TOOL = join(ROOT, 'tools/ci/rule22-exports-map.mjs');

const MUTANTS = [
  ['QM-1 whole-segment run check dropped', '    if (segmentRunMatchesTerm(segs, t)) return t; // whole consecutive segments, never the joined name\n', '', /qr33-run-red-0/],
  ['QM-2 joined-name substring scan added', '    if (segs.some((s) => s.includes(t))) return t; // substring scan, within one segment only\n', '    if (segs.some((s) => s.includes(t))) return t; // substring scan, within one segment only\n    if (segs.join(\'\').includes(t)) return t;\n', /qr33-seg-green start_page/],
  ['QM-3 run check across the joined name (any substring of the run)', '      if (segmentMatchesTerm(run, t)) return true;', '      if (run.includes(t)) return true;', /qr33-seg-green/],
  ['QM-4 constructor parameter properties not scanned', '      for (const name of constructorParameterProperties(st)) member(name);\n', '', /g42-ctor-param-public/],
  ['QM-5 type-literal members not scanned', '    if (ts.isTypeLiteralNode(n)) for (const m of n.members)', '    if (false) for (const m of n.members)', /g42-type-literal-member/],
  ['QM-6 namespace members not scanned', '      if (body && ts.isModuleBlock(body)) for (const b of exportedBindingsOf(body.statements))', '      if (false) for (const b of exportedBindingsOf(body.statements))', /g42-namespace-member/],
  ['QM-8 (QM-H1) run check only from segment 0', '  for (let i = 0; i < segs.length; i++) {\n    let run = segs[i];', '  for (let i = 0; i < Math.min(segs.length, 1); i++) {\n    let run = segs[i];', /qr33-run-red-6/],
  ['QM-7 run check ignores plurals', '      if (segmentMatchesTerm(run, t)) return true;', '      if (run === t) return true;', /qr33-run-red-3/],
];

test('QR-33 run check: split term-11 forms red, run controls and the 8 boundary names green', () => {
  for (const n of qr33RunRed()) assert.ok(qr33Hit(n), `${n} must be red`);
  for (const n of [...QR33_BOUNDARY_GREEN, ...qr33RunGreen()]) assert.equal(qr33Hit(n), null, `${n} must be green`);
  assert.equal(QR33_BOUNDARY_GREEN.length, 8);
});

for (const [label, from, to, killer] of MUTANTS) {
  test(`QR-33 mutant ${label} is killed by rule22 --self-test`, () => {
    const src = readFileSync(TOOL, 'utf8');
    assert.equal(src.split(from).length - 1, 1, `anchor must occur once: ${label}`);
    const file = join(ROOT, 'tools/ci', `_scratch-qr33-${label.slice(0, 4).replace(/[^A-Za-z0-9]/g, '')}.mjs`);
    try {
      writeFileSync(file, src.replace(from, () => to));
      const r = spawnSync(process.execPath, [file, '--self-test'], { encoding: 'utf8', timeout: 120_000, cwd: ROOT });
      const out = `${r.stdout}\n${r.stderr}`;
      assert.notEqual(r.status, 0, `${label} survived:\n${out}`);
      assert.match(out, killer, `${label}: expected killer ${killer}:\n${out}`);
    } finally { rmSync(file, { force: true }); }
  });
}
