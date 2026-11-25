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

// EG-3 / G-45 (HoQ report c9d7c93..dbd4e00, addendum 1 A7): the entry guard is enforced STRUCTURALLY at the
// spawn layer (tools/ci/entropy-backstop.mjs), not by matching source text. The text contract that stood
// here (runnerContractText / runnerContractFindings, with a directory exemption) is removed:
//   - every battery tool spawn (dieharder, tu01-driver, assess, RNG_test; as the executable or as any argv
//     or shell word) is refused by the backstop unless it comes from launchEvidenceTool inside an open grant;
//   - a grant is opened only by the backstop's openEvidenceGrant, which itself runs assertEvidenceRunReady
//     (root fixed by its own URL) and opens nothing unless that returned OK; each launch re-runs the guard;
//   - interpreters (python, perl, sh, env, ...) are never spawned; no path or directory is exempt;
//   - startEvidenceRun is the guarded entry export: it refuses without the backstop preload, runs the guard,
//     opens the grant, hands the callback a launcher bound to that grant, and closes the grant afterwards.
const MARK = Symbol.for('open-rng-engine/entropy-backstop/v1');

function backstopEvidence() {
  const desc = Object.getOwnPropertyDescriptor(globalThis, MARK);
  const ev = desc && !desc.writable && !desc.configurable && desc.value && desc.value.evidence;
  if (!ev || typeof ev.open !== 'function' || typeof ev.launch !== 'function' || typeof ev.close !== 'function') {
    throw new Error('evidence run refused: start it under the entropy-backstop preload (node --import ./tools/ci/entropy-backstop.mjs), G-45');
  }
  return ev;
}

// The sanctioned (and only) runner entry. fn receives { launch(file, args, options), launchStream(file, args,
// options) } (launchStream: R-G64 asynchronous spawn, same checks) and may be async.
export async function startEvidenceRun(fn) {
  const ev = backstopEvidence();
  assertEvidenceRunReady();
  const g = await ev.open();
  try {
    const launchStream = typeof ev.launchStream === 'function' ? (file, args, options) => ev.launchStream(g, file, args, options) : null;
    return await fn(Object.freeze({ launch: (file, args, options) => ev.launch(g, file, args, options), launchStream }));
  } finally {
    ev.close(g);
  }
}

// HM-19 / HM-21 (static, defence in depth; not the enforcement): the repo holds no shell, Python or other
// interpreter scripts anywhere (no directory exempt), so a battery cannot be driven from a script the
// backstop never sees. Files are judged by extension and by shebang, not by their text.
export const SCRIPT_EXTENSIONS = Object.freeze(['sh', 'bash', 'zsh', 'ksh', 'csh', 'fish', 'py', 'pyw', 'pl', 'pm', 'rb', 'php', 'lua', 'tcl', 'r', 'ps1', 'bat', 'cmd', 'awk', 'exp', 'jl']);

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

export function scriptFileFinding(rel, head) {
  const ext = (rel.split('/').pop().match(/\.([^.]+)$/) || [, ''])[1].toLowerCase();
  if (SCRIPT_EXTENSIONS.includes(ext)) return `G-45: ${rel} is a .${ext} script (no interpreter scripts in the repo)`;
  const h = String(head);
  if (h.startsWith('#!') && !/^#!\s*\/usr\/bin\/env\s+node(?:\s|$)/.test(h)) return `G-45: ${rel} has a non-node shebang`;
  return null;
}

export function scriptFileFindings(root = ROOT, files, read = (rel) => readFileSync(join(root, rel)).subarray(0, 128).toString('latin1')) {
  const f = [];
  for (const rel of files ?? walk(root)) {
    let head = '';
    try { head = read(rel); } catch { continue; }
    const why = scriptFileFinding(rel, head);
    if (why) f.push(why);
  }
  return f;
}
