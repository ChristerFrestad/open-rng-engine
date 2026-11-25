// A25-6 (i), (ii), (iii), (v) and A29-3: behavioural cases for A25-2 full code closure (HoQ addendum 1 L638-L647, L786;
// CTO split /workspace/rng-backup/a25-2/A25-2-SPLIT-v1.md, interface v2 = Addendum C, sha256 1f832505...). Owner: TE.
// Each case runs a child node under the preload in helper mode (ENTROPY_BACKSTOP_HELPER=a25) on a TEMP COPY of src/
// and tools/ci (never on this tree) and checks its exact exit code:
//   86 EXIT_A25_TOKEN, 89 EXIT_A25_MANIFEST_OUTSIDE, 90 EXIT_A25_MANIFEST_DIGEST, 91 EXIT_A25_CODEGEN.
// Written against interface v2 (Addendum C) before Backend integrates tools/ci/a25-manifest.mjs and the load hook, so
// the A25-2 cases FAIL until then (expected). The A29-3 cases run on 150edc5d as is.
// Bare parent: a preloaded parent (npm test) re-preloads every node child and refuses one that never proves the
// preload, and the hostile-tree/manifest cases need bare children (buildManifest). Under npm test this file only checks
// the wiring and runs the A29-3 cases; tools/ci/a25-2-mutants.mjs runs it bare (baseline must be green, 0 skipped).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { child } from './fixtures/a25-child.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MARK = "Symbol.for('open-rng-engine/entropy-backstop/v1')";
const BARE = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')] === undefined;
const EXIT = Object.freeze({ TOKEN: 86, OUTSIDE: 89, DIGEST: 90, CODEGEN: 91 });
// Interface v2 (Addendum C): ENTROPY_BACKSTOP_MANIFEST only LOCATES the manifest JSON
// { version: 1, root, entries: { '<posix relpath>': '<sha256 hex>' } }; the launcher deletes any inherited value and sets
// its own; the D22-7 header binds manifest_sha256 and the preload exits 90 before any module loads when the file is
// missing, unreadable, or its sha256 differs from the header-bound digest.
const MANIFEST_ENV = 'ENTROPY_BACKSTOP_MANIFEST';
// The manifest sha256 is bound in the D22-7 header and reaches the preload ONLY through the grant (Addendum C; CTO
// 21:29): never through a plain inheritable env var, which any spawner could set. This file therefore hard-codes NO
// carrier: every helper env is built by the launcher's own export, and the forged-sha cases check that a sha offered
// outside the grant is ignored.
// ---- OPEN: named exports TE asked Backend for (the mutant runner overrides them; NOT-APPLIED until they exist) ----
//   tools/ci/a25-manifest.mjs                 readManifest(path, expectedSha256) -> manifest (the preload's header check)
//   verification/harness/stream-launcher.mjs  helperSpawnEnv(baseEnv, { token, manifestPath, manifestSha256 }) -> env
//                                             (the builder realSpawnPart uses; binds the sha into the grant)
// The token passed here is a test token; if the preload must verify it against a live grant, Backend says how a
// direct test spawn obtains one, and only launchEnv() below changes.
// Env names used ONLY as forged values (any spawner could set them); the preload must ignore all of them.
const FORGED_SHA_NAMES = ['ENTROPY_BACKSTOP_MANIFEST_SHA256', 'ENTROPY_BACKSTOP_MANIFEST_DIGEST', 'ENTROPY_BACKSTOP_HEADER_MANIFEST_SHA256', 'MANIFEST_SHA256'];
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

function bareEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k === 'NODE_OPTIONS' || k.startsWith('ENTROPY_BACKSTOP_') || FORGED_SHA_NAMES.includes(k)) delete env[k];
  return { ...env, ...extra };
}
// A temp tree: src/, tools/ci/, package.json and tsconfig.json copied; `edit` rewrites files ({ path: (text) => text }),
// `add` writes new files ({ path: text }).
function tree({ edit = {}, add = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'a25-2-'));
  cpSync(join(ROOT, 'src'), join(root, 'src'), { recursive: true });
  cpSync(join(ROOT, 'tools/ci'), join(root, 'tools/ci'), { recursive: true });
  for (const f of ['package.json', 'tsconfig.json']) if (existsSync(join(ROOT, f))) cpSync(join(ROOT, f), join(root, f));
  for (const [p, fn] of Object.entries(edit)) { const t = readFileSync(join(root, p), 'utf8'), n = fn(t); assert.notEqual(n, t, `edit of ${p} changed nothing`); writeFileSync(join(root, p), n); }
  for (const [p, text] of Object.entries(add)) { mkdirSync(join(root, p, '..'), { recursive: true }); writeFileSync(join(root, p), text); }
  return root;
}
// Every file in the tree, as posix relpaths, sorted.
function listFiles(root, dir = '') {
  const out = [];
  for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = dir ? `${dir}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...listFiles(root, rel)); else out.push(rel);
  }
  return out.sort();
}
// buildManifest(root, relpaths) from the tree's own tools/ci/a25-manifest.mjs, in a bare child (importing it here could
// install the preload in this process). The manifest lists every file of the tree except `outside` (files a case adds
// to load from outside the manifest). Written next to, not inside, the tree. Returns its path, the parsed manifest and
// the sha256 of its exact bytes (what the header binds).
function manifestFor(root, outside = []) {
  const mod = join(root, 'tools/ci/a25-manifest.mjs');
  assert.ok(existsSync(mod), 'tools/ci/a25-manifest.mjs is missing (Backend integration pending)');
  const relpaths = listFiles(root).filter((p) => !outside.includes(p));
  const script = `const M = await import(${JSON.stringify(pathToFileURL(mod).href)});
const m = await M.buildManifest(${JSON.stringify(root)}, ${JSON.stringify(relpaths)});
process.stdout.write(typeof m === 'string' ? m : JSON.stringify(m));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: root, env: bareEnv(), encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, `buildManifest failed: ${r.stderr}`);
  const m = JSON.parse(r.stdout);
  assert.equal(m.version, 1, 'manifest version 1');
  assert.equal(m.root, root, 'manifest root is the absolute tree root');
  assert.deepEqual(Object.keys(m.entries).sort(), relpaths, 'manifest entries are exactly the given relpaths');
  for (const p of relpaths) assert.equal(m.entries[p], sha256(readFileSync(join(root, p))), `entry ${p} is the sha256 of its bytes`);
  const path = `${root}.manifest.json`;
  writeFileSync(path, r.stdout);
  return { path, m, sha: sha256(readFileSync(path)) };
}
// The helper env from the launcher's own builder (this tree's verification/harness/stream-launcher.mjs, imported in a
// bare child): helperSpawnEnv(base, { token, manifestPath, manifestSha256 }).
const LAUNCHER = join(ROOT, 'verification/harness/stream-launcher.mjs');
function launchEnv(base, { manifestPath, manifestSha256 }) {
  const script = `const L = await import(${JSON.stringify(pathToFileURL(LAUNCHER).href)});
if (typeof L.helperSpawnEnv !== 'function') { process.stderr.write('helperSpawnEnv is not exported (Backend integration pending)'); process.exit(3); }
process.stdout.write(JSON.stringify(await L.helperSpawnEnv(${JSON.stringify(base)}, ${JSON.stringify({ token: 'grant-1@1#te', manifestPath, manifestSha256 })})));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: ROOT, env: bareEnv(), encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, `helperSpawnEnv: ${r.stderr}`);
  return JSON.parse(r.stdout);
}
// Runs `main` (a path inside root) under the tree's preload in helper mode with the manifest bound at manifestSha.
// `inherited`: extra vars in the env the launcher starts from; `forged`: vars written over the launcher's env at spawn.
function helper(root, main, manifestPath, manifestSha, extra = {}, { inherited = {}, forged = {} } = {}) {
  const env = { ...launchEnv(bareEnv(inherited), { manifestPath, manifestSha256: manifestSha }), ...extra, ...forged };
  assert.equal(env.ENTROPY_BACKSTOP_HELPER, 'a25', 'the launcher sets helper mode');
  const r = spawnSync(process.execPath, ['--import', join(root, 'tools/ci/entropy-backstop.mjs'), join(root, main)], { cwd: root, env, encoding: 'utf8', timeout: 120000 });
  return { status: r.status, out: r.stdout, err: r.stderr };
}
const clean = (root) => { for (const p of [root, `${root}.manifest.json`, `${root}.swap.json`]) rmSync(p, { recursive: true, force: true }); };
// One scenario: build the tree and the manifest (every file but `outside`), optionally change tree bytes after the
// manifest (`after`) or the manifest file / header-bound sha (`header`: ({ root, path, sha, m }) => { path, sha }), run.
function scenario({ main, edit, add, outside = [], after, header, env, spoof }) {
  const root = tree({ edit, add: { ...add, 'te-main.mjs': main } });
  try {
    let { path, sha, m } = manifestFor(root, outside);
    if (after) for (const [p, fn] of Object.entries(after)) { const f = join(root, p), t = readFileSync(f, 'utf8'), n = fn(t); assert.notEqual(n, t); writeFileSync(f, n); }
    if (header) ({ path, sha } = header({ root, path, sha, m }));
    return helper(root, 'te-main.mjs', path, sha, env, spoof ? spoof({ root, path, sha }) : {});
  } finally { clean(root); }
}
const HEAD = `import * as E from './src/index.ts';\nconst M = () => globalThis[${MARK}].helper;\n`;
const ok = (r) => { assert.equal(r.status, 0, `${r.status} ${r.err}`); assert.match(r.out, /ALIVE/); };
const dies = (r, code, why) => {
  assert.equal(r.status, code, `want exit ${code}, got ${r.status}: ${r.err}`);
  assert.doesNotMatch(r.out, /ALIVE|ROGUE-RAN|CODEGEN-RAN|NOT-ABORTED/);
  if (why) assert.match(r.err, why);
};

test('A25-2 wiring: tools/ci/a25-2-mutants.mjs runs this file bare (no case here is skipped)', () => {
  const t = readFileSync(join(ROOT, 'tools/ci/a25-2-mutants.mjs'), 'utf8');
  assert.match(t, /const TEST_FILE = 'test\/r-g64-a25-2\.test\.mjs';/);
  assert.match(t, /delete env\.NODE_OPTIONS/);
});

// ---------------- A29-3: the gate token is cleared in finally (test-only seam: makeHelperGate, normal mode) ----------------
// The shipped install builds the gate only as makeHelperGate(origFill) (pinned in test/r-g64-a25.test.mjs), so the
// installed gate runs this same finally. The real randomFillSync does not throw on a target the gate accepts (detached
// and shrunk-resizable views were tried on node 24: no throw), so the throwing fill goes through the factory seam.
const SEAM = `const B = await import(new URL('tools/ci/entropy-backstop.mjs', ROOTURL).href);\n`;
const seam = (code) => child(SEAM + code, { mode: null });
test('A29-3: a fill that throws on the first call: the same error propagates, the token is clear, the next call fills', () => {
  const r = seam(`const boom = new Error('FILL-THREW'); let n = 0;
const H = B.makeHelperGate((t) => { if (++n === 1) throw boom; t[0] = 7; }, { walk: () => {} });
let same = false; try { H.gate(new Uint8Array(4)); } catch (e) { same = e === boom; }
const tokenAfter = H.tokenSet(); const u = H.gate(new Uint8Array(4));
process.stdout.write(JSON.stringify({ same, tokenAfter, second: u[0], counts: H.counts() }));`);
  assert.equal(r.status, 0, `${r.status} ${r.err}`);
  assert.deepEqual(JSON.parse(r.out), { same: true, tokenAfter: false, second: 7, counts: { gate_calls: 2, walks: 2 } });
});
test('A29-3: throws in the middle of a run (calls 3, 4 and 6 of 8), including non-Error values: token clear after each, the rest fill', () => {
  const r = seam(`const T = { 3: 'str', 4: undefined, 6: new RangeError('r') }; let n = 0; const log = [];
const H = B.makeHelperGate((t) => { n++; if (n in T) throw T[n]; t[0] = n; }, { walk: () => {} });
for (let i = 1; i <= 8; i++) { try { log.push(H.gate(new Uint8Array(1))[0]); } catch (e) { log.push(e === T[i] ? 'same' : 'OTHER'); } log.push(H.tokenSet()); }
process.stdout.write(JSON.stringify({ log, counts: H.counts() }));`);
  assert.equal(r.status, 0, `${r.status} ${r.err}`);
  assert.deepEqual(JSON.parse(r.out), { log: [1, false, 2, false, 'same', false, 'same', false, 5, false, 'same', false, 7, false, 8, false], counts: { gate_calls: 8, walks: 8 } });
});
test('A29-3: after a throw the token works again: re-entering the gate from the next fill exits 86', () => {
  const r = seam(`let n = 0, H;
H = B.makeHelperGate((t) => { n++; if (n === 1) throw new Error('FILL-THREW'); if (n === 2) { process.stdout.write('IN-FILL-2 ' + H.tokenSet()); H.gate(new Uint8Array(1)); process.stdout.write('NOT-ABORTED'); } }, { walk: () => {} });
try { H.gate(new Uint8Array(1)); } catch {} H.gate(new Uint8Array(1)); process.stdout.write('NOT-ABORTED');`);
  assert.equal(r.status, EXIT.TOKEN, `${r.status} ${r.err}`);
  assert.equal(r.out, 'IN-FILL-2 true');
  assert.match(r.err, /gate re-entered while the token is set \(exit 86\)/);
});

if (BARE) {
  test('A25-2 bare: exit constants are the reserved values and distinct (split v1)', () => {
    const txt = readdirSync(join(ROOT, 'tools/ci')).filter((f) => f.endsWith('.mjs') && f !== 'a25-2-mutants.mjs').map((f) => readFileSync(join(ROOT, 'tools/ci', f), 'utf8')).join('\n');
    for (const [n, v] of [['EXIT_A25_TOKEN', 86], ['EXIT_A25_MANIFEST_OUTSIDE', 89], ['EXIT_A25_MANIFEST_DIGEST', 90], ['EXIT_A25_CODEGEN', 91]]) {
      const m = new RegExp(`\\b${n}\\s*=\\s*(\\d+)`).exec(txt); assert.ok(m, `${n} is defined in tools/ci`); assert.equal(Number(m[1]), v, n);
    }
  });

  // ---------------- A25-6 (i): a non-manifest module calls randomBytes directly -> 89 ----------------
  // The rogue file is loaded with createRequire, so no static walk from the entry can put it in the manifest, and it is
  // not a dynamic import() (that is the lockdown's 94). It must be refused at load: its randomBytes line never runs.
  const ROGUE = `require('node:crypto').randomBytes(4); process.stdout.write('ROGUE-RAN');\n`;
  const ROGUE_ESM = `import { randomBytes } from 'node:crypto'; randomBytes(4); process.stdout.write('ROGUE-RAN');\n`;
  const loadRogue = (spec) => `${HEAD}import { createRequire } from 'node:module';\nE.integer(0, 10);\ncreateRequire(import.meta.url)(${JSON.stringify(spec)});\nprocess.stdout.write('ALIVE');\n`;
  test('A25-6(i) control: the same tree and manifest without the rogue load exit 0', () => {
    ok(scenario({ main: `${HEAD}E.integer(0, 10); E.shuffle([1, 2, 3]); process.stdout.write('ALIVE');\n`, add: { 'rogue.cjs': ROGUE }, outside: ['rogue.cjs'] }));
  });
  const OUTSIDE = {
    'a .cjs file': ['./rogue.cjs', { 'rogue.cjs': ROGUE }],
    'a .js file in node_modules': ['rogue-pkg', { 'node_modules/rogue-pkg/package.json': '{"name":"rogue-pkg","main":"index.js"}', 'node_modules/rogue-pkg/index.js': ROGUE }],
    'an .mjs file through require(esm)': ['./rogue.mjs', { 'rogue.mjs': ROGUE_ESM }],
    'a .ts file next to src': ['./src/rogue.ts', { 'src/rogue.ts': `// @ts-expect-error no typings\nimport { randomBytes } from 'node:crypto';\nrandomBytes(4); process.stdout.write('ROGUE-RAN');\n` }],
  };
  for (const [name, [spec, add]] of Object.entries(OUTSIDE)) {
    test(`A25-6(i): ${name} outside the manifest calling randomBytes exits 89 before it runs`, () => {
      dies(scenario({ main: loadRogue(spec), add, outside: Object.keys(add) }), EXIT.OUTSIDE);
    });
  }

  // ---------------- A25-6 (ii): an approved module's bytes change after the manifest (srcDigest_before) -> 90 ----------------
  const DIGEST = {
    'src/index.ts gains a direct primitive call': { 'src/index.ts': (t) => `${t}\n(globalThis as any).crypto.getRandomValues(new Uint8Array(1));\n` },
    'src/entropy/index.ts gains one comment byte': { 'src/entropy/index.ts': (t) => `${t}\n//\n` },
    'the entry itself changes': { 'te-main.mjs': (t) => t.replace("process.stdout.write('ALIVE');", "process.stdout.write('ALIVE'); ") },
  };
  for (const [name, after] of Object.entries(DIGEST)) {
    test(`A25-6(ii): ${name} after the manifest: exit 90`, () => {
      dies(scenario({ main: `${HEAD}E.integer(0, 10); process.stdout.write('ALIVE');\n`, after }), EXIT.DIGEST);
    });
  }
  test('A25-6(ii): a manifest module rewritten on disk after start, then lazily loaded: exit 90', () => {
    const main = `${HEAD}import { writeFileSync } from 'node:fs';\nE.integer(0, 10);\nwriteFileSync(new URL('./lazy.mjs', import.meta.url), "globalThis.crypto.getRandomValues(new Uint8Array(1)); process.stdout.write('ROGUE-RAN');\\n");\nawait import('./lazy.mjs');\nprocess.stdout.write('ALIVE');\n`;
    dies(scenario({ main, add: { 'lazy.mjs': 'export const x = 1;\n' } }), EXIT.DIGEST);
  });
  test('A25-6(ii) control: the lazy manifest module unchanged loads and exits 0', () => {
    ok(scenario({ main: `${HEAD}E.integer(0, 10);\nconst L = await import('./lazy.mjs');\nif (L.x === 1) process.stdout.write('ALIVE');\n`, add: { 'lazy.mjs': 'export const x = 1;\n' } }));
  });

  // ---------------- A25-2 header binding (Addendum C; CTO 21:14, 21:23): the manifest FILE itself -> 90 before any module loads ----------------
  // The env var only locates the file; the header-bound sha256 decides. Each main prints MAIN-START first, so an empty
  // stdout proves the exit came before the main entry ran.
  const EARLY = `process.stdout.write('MAIN-START');\n${HEAD}E.integer(0, 10); process.stdout.write('ALIVE');\n`;
  const early = (r) => { dies(r, EXIT.DIGEST); assert.equal(r.out, '', 'exit 90 before the main entry runs'); };
  test('A25-2 header control: the bound manifest at the bound sha runs the main entry', () => {
    const r = scenario({ main: EARLY }); ok(r); assert.match(r.out, /^MAIN-START/);
  });
  test('A25-2 header: the manifest file swapped for another valid manifest (sha no longer the header-bound one): exit 90', () => {
    // The swap lists the same files plus rogue.cjs: valid JSON, version 1, right root; only its bytes' sha differs.
    early(scenario({ main: EARLY, add: { 'rogue.cjs': ROGUE }, outside: ['rogue.cjs'], header: ({ root, sha, m }) => {
      const swapped = { ...m, entries: { ...m.entries, 'rogue.cjs': sha256(readFileSync(join(root, 'rogue.cjs'))) } };
      const p = `${root}.swap.json`; writeFileSync(p, JSON.stringify(swapped)); assert.notEqual(sha256(readFileSync(p)), sha);
      return { path: p, sha };
    } }));
  });
  test('A25-2 header: the same manifest file under a different header-bound sha256: exit 90', () => {
    early(scenario({ main: EARLY, header: ({ path, sha }) => ({ path, sha: (sha[0] === '0' ? '1' : '0') + sha.slice(1) }) }));
  });
  test('A25-2 header: the manifest file is missing: exit 90', () => {
    early(scenario({ main: EARLY, header: ({ root, sha }) => ({ path: `${root}.does-not-exist.json`, sha }) }));
  });
  test('A25-2 header: the manifest path is unreadable (a directory): exit 90', () => {
    early(scenario({ main: EARLY, header: ({ root, sha }) => ({ path: join(root, 'src'), sha }) }));
  });
  test('A25-2 header: the manifest file loses its last byte after binding: exit 90', () => {
    early(scenario({ main: EARLY, header: ({ path, sha }) => { const b = readFileSync(path); writeFileSync(path, b.subarray(0, b.length - 1)); return { path, sha }; } }));
  });

  // A sha offered OUTSIDE the grant (CTO 21:29): the manifest file is swapped for a valid one (rogue.cjs added), the grant
  // still binds the ORIGINAL sha, and the swapped file's own sha is offered under every FORGED_SHA_NAMES name, both
  // inherited by the launcher and written over its env at spawn. The preload must ignore them all: exit 90, main never runs.
  const swapTo = ({ root, sha, m }) => {
    const swapped = { ...m, entries: { ...m.entries, 'rogue.cjs': sha256(readFileSync(join(root, 'rogue.cjs'))) } };
    const p = `${root}.swap.json`; writeFileSync(p, JSON.stringify(swapped)); assert.notEqual(sha256(readFileSync(p)), sha);
    return { path: p, sha };
  };
  const forgeAll = (v) => Object.fromEntries(FORGED_SHA_NAMES.map((k) => [k, v]));
  test('A25-2 header: a forged sha (the swapped file\'s own) inherited by the launcher is ignored: exit 90', () => {
    early(scenario({ main: EARLY, add: { 'rogue.cjs': ROGUE }, outside: ['rogue.cjs'], header: swapTo,
      spoof: ({ path }) => ({ inherited: forgeAll(sha256(readFileSync(path))) }) }));
  });
  test('A25-2 header: a forged sha (the swapped file\'s own) written into the helper env at spawn is ignored: exit 90', () => {
    early(scenario({ main: EARLY, add: { 'rogue.cjs': ROGUE }, outside: ['rogue.cjs'], header: swapTo,
      spoof: ({ path }) => ({ forged: forgeAll(sha256(readFileSync(path))) }) }));
  });
  test('A25-2 header control: forged sha values that EQUAL the bound one change nothing (the forgery cases fail on the swap, not on the extra vars)', () => {
    const r = scenario({ main: EARLY, spoof: ({ sha }) => ({ inherited: forgeAll(sha), forged: forgeAll(sha) }) }); ok(r);
  });

  // ---------------- A25-2 launcher (Addendum C): inherited values never reach a helper ----------------
  // Behavioural on the launcher's env builder (helperSpawnEnv, the one realSpawnPart must use; export requested from Backend).
  const OWN = { manifestPath: '/te/own.manifest.json', manifestSha256: 'a'.repeat(64) };
  test('A25-2 launcher: an inherited manifest locator, forged shas and NODE_OPTIONS are replaced or dropped', () => {
    const bad = 'f'.repeat(64);
    const e = launchEnv({ PATH: '/usr/bin', [MANIFEST_ENV]: '/hostile/manifest.json', ...forgeAll(bad), NODE_OPTIONS: '--require /hostile.cjs' }, OWN);
    assert.equal(e[MANIFEST_ENV], '/te/own.manifest.json');
    assert.ok(!('NODE_OPTIONS' in e));
    for (const [k, v] of Object.entries(e)) assert.ok(!String(v).includes(bad), `inherited forged sha reaches the helper as ${k}`);
  });
  test('A25-2 launcher: with nothing inherited the launcher still sets its own manifest locator', () => {
    assert.equal(launchEnv({ PATH: '/usr/bin' }, OWN)[MANIFEST_ENV], '/te/own.manifest.json');
  });

  // ---------------- A25-6 (iii): eval / new Function code calls a CSPRNG primitive -> 91 ----------------
  // 91, not 86: the code generation itself must be refused, before the primitive's own exit 86 could fire.
  const P = `globalThis.crypto.getRandomValues(new Uint8Array(1))`;
  const CODEGEN = {
    'direct eval': `eval(${JSON.stringify(P)});`,
    'indirect eval': `(0, eval)(${JSON.stringify(P)});`,
    'new Function': `new Function(${JSON.stringify('return ' + P)})();`,
    'Function without new': `Function(${JSON.stringify('return ' + P)})();`,
    'AsyncFunction constructor': `await (async () => {}).constructor(${JSON.stringify('return ' + P)})();`,
    'GeneratorFunction constructor': `(function* () {}).constructor(${JSON.stringify('yield ' + P)})().next();`,
    'eval reaching randomBytes through getBuiltinModule': `eval("process.getBuiltinModule('node:crypto').randomBytes(4)");`,
  };
  for (const [name, code] of Object.entries(CODEGEN)) {
    test(`A25-6(iii): ${name} calling a CSPRNG primitive exits 91`, () => {
      dies(scenario({ main: `${HEAD}E.integer(0, 10);\n${code}\nprocess.stdout.write('CODEGEN-RAN');\n` }), EXIT.CODEGEN);
    });
  }

  // ---------------- A25-6 (v): a callback from inside the approved entry calls a primitive -> 86 on every call ----------------
  // src/te-cb.ts is a manifest module that is not an entry; fillBuffer (the approved entry) calls it first on every call.
  // At gate call TE_REENTER_AT it calls one primitive. Note: in the installed gate the token is set only during the
  // native fill, so a JS callback always runs with it clear; the abort is the wrap's helper-mode 86 either way. The
  // indices cover the walked range (< 10^4), sampled (i mod 2^12 = 0) and unsampled calls after 10^4: the abort must not
  // depend on the A25-4 sample.
  const CB = `const P = Symbol.for('open-rng-engine/entropy-backstop/v1');
export function teCb(): void {
  const h = (globalThis as any)[P].helper; const i = h.counts().gate_calls;
  if (String(i) !== process.env.TE_REENTER_AT) return;
  process.stdout.write('REENTER ' + i + '\\n');
  const how = process.env.TE_REENTER_HOW, c = (process as any).getBuiltinModule('node:crypto');
  if (how === 'getRandomValues') (globalThis as any).crypto.getRandomValues(new Uint8Array(1));
  else if (how === 'randomBytes') c.randomBytes(4);
  else if (how === 'randomFillSync') c.randomFillSync(new Uint8Array(4));
  else if (how === 'randomUUID') c.randomUUID();
  process.stdout.write('NOT-ABORTED\\n');
}
`;
  const cbEdit = { 'src/entropy/index.ts': (t) => t.replace("import { randomFillSync } from 'node:crypto';", "import { randomFillSync } from 'node:crypto';\nimport { teCb } from '../te-cb.ts';").replace('export function fillBuffer(target: Uint8Array): Uint8Array {\n', 'export function fillBuffer(target: Uint8Array): Uint8Array {\n  teCb();\n') };
  const cbMain = (at) => `${HEAD}while (M().counts().gate_calls <= ${at}) E.integer(0, 1000);\nprocess.stdout.write('ALIVE ' + M().counts().gate_calls);\n`;
  const reenter = (at, how) => scenario({ main: cbMain(Math.max(at, 12290)), edit: cbEdit, add: { 'src/te-cb.ts': CB }, env: { TE_REENTER_AT: String(at), TE_REENTER_HOW: how } });
  test('A25-6(v) control: the callback that never fires leaves the run green past 12290 gate calls', () => {
    const r = reenter(-1, 'getRandomValues'); ok(r); assert.ok(Number(/ALIVE (\d+)/.exec(r.out)[1]) > 12290);
  });
  const CASES = [...[0, 1, 9999, 10000, 10001, 12288, 12289].map((i) => [i, 'getRandomValues']),
    ...['randomBytes', 'randomFillSync', 'randomUUID'].flatMap((h) => [[0, h], [10001, h]])];
  for (const [at, how] of CASES) {
    test(`A25-6(v): callback re-entry calling ${how} at gate call ${at} exits 86 at that call`, () => {
      const r = reenter(at, how);
      assert.equal(r.status, EXIT.TOKEN, `${r.status} ${r.err}`);
      assert.equal(r.out, `REENTER ${at}\n`);
      assert.match(r.err, /called in helper mode .*\(exit 86\)/);
    });
  }
}
