// Evidence-run entry point guard. Decision rule v1 (FROZEN 5d09c75a) rule 18 and the rule 8 / 15 / 17
// preconditions: no counted evidence run starts unless the harness is READY. The PH0 gate (check:ph0)
// reports readiness but does not fail on it; this guard is what blocks a run.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dfReadiness } from './df-table.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

export function harnessReadiness(root = ROOT) {
  const kTests = JSON.parse(readFileSync(join(root, 'verification/k-tests-v1.1.json'), 'utf8')).tests;
  const df = dfReadiness(kTests);
  return { ready: df.ready, df };
}

// Every evidence-run start must call this first. It throws while anything is open.
export function assertEvidenceRunReady(root = ROOT) {
  const r = harnessReadiness(root);
  if (!r.ready) {
    throw new Error(`harness NOT-READY: rule 8 df open for ${r.df.open.length} of ${r.df.dfNull} df-null entries (${r.df.open.slice(0, 3).join(', ')}${r.df.open.length > 3 ? ', ...' : ''})`);
  }
  return r;
}

// EG-3 (HoQ b15a2ff5 report): the evidence runner must call the entry guard. No runner exists yet, so this
// is a contract enforced in check:ph0: any tracked source file outside test/ that starts a battery tool
// (spawn/exec of dieharder, tu01-driver, STS assess or PractRand RNG_test) or imports the collector must
// call assertEvidenceRunReady( (or startEvidenceRun( ) textually BEFORE the first such use.
export const RUNNER_CONTRACT_EXEMPT = Object.freeze(['verification/harness/evidence-entry.mjs', 'verification/harness/collector.mjs']);
const START = /\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(\s*[^)]*?\b(?:dieharder|tu01-driver|assess|RNG_test)\b/;
const IMPORT_COLLECTOR = /(?:from\s*|import\s*\(\s*)['"][^'"]*collector\.mjs['"]/;
const GUARD = /\b(?:assertEvidenceRunReady|startEvidenceRun)\s*\(/;

export function runnerContractText(text) {
  const s = String(text);
  const uses = [START.exec(s), IMPORT_COLLECTOR.exec(s)].filter(Boolean).map((m) => m.index);
  if (!uses.length) return null;
  const first = Math.min(...uses);
  const g = GUARD.exec(s);
  if (!g) return 'starts an evidence run without the entry guard';
  if (g.index > first) return 'calls the entry guard only after starting the run';
  return null;
}

// Every file under root except .git and node_modules (no git needed, so scratch copies are scanned too).
function walk(root, rel = '') {
  const out = [];
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...walk(root, r));
    else if (e.isFile()) out.push(r);
  }
  return out;
}

export function runnerContractFindings(root = ROOT, files) {
  const list = files ?? walk(root);
  const f = [];
  for (const rel of list) {
    if (rel.startsWith('test/') || rel.startsWith('node_modules/') || RUNNER_CONTRACT_EXEMPT.includes(rel)) continue;
    if (!/\.(?:mjs|cjs|js|ts|mts|cts|sh|py)$/.test(rel)) continue;
    let text;
    try { text = readFileSync(join(root, rel), 'utf8'); } catch { continue; }
    const why = runnerContractText(text);
    if (why) f.push(`EG-3: ${rel} ${why} (assertEvidenceRunReady)`);
  }
  return f;
}

// The sanctioned runner entry: guard first, then the run.
export function startEvidenceRun(fn, root = ROOT) {
  assertEvidenceRunReady(root);
  return fn();
}
