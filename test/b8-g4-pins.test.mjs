import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { G4_DIR, G4_TYPESCRIPT_5_9_3_SHA256, G4_PINS_JSON_SHA256, fileSha256 } from '../tools/ci/b8-dependencies.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PINS_REL = `${G4_DIR}/G4-PINS.json`;
// Sha256 of verification/g4/G4-PINS.json lives in b8-dependencies.mjs so check:ph0 enforces it (G-44).

test('G-38: G4-PINS.json sha256 is pinned', () => {
  const buf = readFileSync(join(ROOT, PINS_REL));
  const sha = createHash('sha256').update(buf).digest('hex');
  assert.equal(sha, G4_PINS_JSON_SHA256);
});

test('G-38: every pinned G4 file matches its sha256', () => {
  const pins = JSON.parse(readFileSync(join(ROOT, PINS_REL), 'utf8'));
  assert.ok(Array.isArray(pins.files) && pins.files.length >= 1);
  for (const ent of pins.files) {
    assert.equal(fileSha256(join(ROOT, ent.file)), ent.sha256, ent.file);
  }
  const ts = pins.files.find((e) => e.file === `${G4_DIR}/g4-typescript-5.9.3.md`);
  assert.ok(ts, 'typescript G4 must be pinned');
  assert.equal(ts.sha256, G4_TYPESCRIPT_5_9_3_SHA256);
});
