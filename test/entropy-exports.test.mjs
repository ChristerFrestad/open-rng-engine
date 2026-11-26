// CTO int-v8 r8: the entropy module exports exactly {fillBuffer}. The raw CSPRNG function is imported (the exact named
// import is the rule 27 L596 pair and fillBuffer's only source) but never re-exported.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const REL = 'src/entropy/index.ts';

test('r8 ENTROPY-EXPORTS: src/entropy/index.ts exports exactly {fillBuffer} (static and at runtime)', () => {
  const src = readFileSync(join(ROOT, REL), 'utf8');
  // Static, on the source text with comments removed. Own scanner, no typescript import: the wiring-mutant runner
  // copies only git-tracked files (no node_modules), and the test must load there (r8 run finding on M86).
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const names = [];
  for (const m of code.matchAll(/\bexport\b\s*([^\n;{(]*)(\{[^}]*\})?/g)) {
    const head = m[1].trim();
    if (m[2] !== undefined && head === '') { for (const el of m[2].slice(1, -1).split(',')) { const t = el.trim(); if (t) names.push(t.split(/\s+as\s+/).pop().trim()); } continue; }
    const d = /^(?:async\s+)?(?:function\*?|const|let|var|class|enum|interface|type|abstract\s+class)\s+([A-Za-z_$][\w$]*)/.exec(head);
    names.push(d ? d[1] : `<unparsed:${head.slice(0, 40)}>`);
  }
  assert.deepEqual(names.sort(), ['fillBuffer'], 'ENTROPY-EXPORTS static exactly {fillBuffer}');
  // Runtime: a child node imports the module and lists the keys of its namespace. Under npm test the G-39 spawn hook
  // gives the child the backstop preload (normal mode, not helper mode), so the import goes through the same hooks.
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(pathToFileURL(join(ROOT, REL)).href)}); process.stdout.write(JSON.stringify(Object.keys(m).sort()));`], { encoding: 'utf8' });
  assert.equal(r.status, 0, `child failed: ${r.stderr}`);
  assert.deepEqual(JSON.parse(r.stdout), ['fillBuffer'], 'ENTROPY-EXPORTS runtime exactly {fillBuffer}');
});
