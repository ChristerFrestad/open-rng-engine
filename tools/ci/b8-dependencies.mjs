#!/usr/bin/env node
// B8 — zero runtime dependencies (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L87 R-1, L143 R-35, L815 B8, L825 item (7).
// `dependencies` must be {} on the core and on every packages/* package.json;
// each devDependency must be an exact pin matching /^\d+\.\d+\.\d+$/; the root
// lockfile must list the same devDependencies, with no runtime dependencies.
// Every non-root lock entry's version equals the pin, resolved starts with
// https://registry.npmjs.org/, and integrity is sha512 (including devOptional).
// optional/peer/bundle(d)Dependencies and overrides must be {} or absent.
//
// G4: every current devDep name@version has a G4 PASS file under verification/g4/
// that names the package.json and package-lock.json sha256 values (HEAD and
// worktree must equal those hashes) and records provenance present/absent.
// A manifest change without a matching new G4 file is red. The `files` field
// and `npm audit signatures` in CI are backlog preconditions for the first
// packed build (do not add them to package.json while this G4 is current).
// G-38: verification/g4/G4-PINS.json lists {file, sha256} for each G4 file. B8
// authenticates each G4 file against that list, requires exactly one top-level
// `VERDICT: PASS` line (markdown-aware: fences, indented code, and blockquotes do not count),
// rejects any other line matching /verdict\s*:/i, pins G4-PINS.json itself, cross-checks the file's Package name@version and
// manifest sha256 values against HEAD and the worktree, and requires every
// devDep to be covered by a pinned and parsed PASS. Missing pin, unpinned G4
// file, sha mismatch, FAIL verdict, missing or duplicate verdict line, wrong
// version, or wrong manifest sha is red.

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

export function uEscape(s) {
  return [...String(s)].map((c) => {
    const code = c.charCodeAt(0);
    return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
      ? '\\u' + code.toString(16).padStart(4, '0')
      : c;
  }).join('');
}
export function uUnescape(s) {
  return String(s).replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export const EXACT_VERSION = /^\d+\.\d+\.\d+$/;
export const REGISTRY_RESOLVED_PREFIX = 'https://registry.npmjs.org/';
export const EMPTY_OR_ABSENT_FIELDS = Object.freeze([
  'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies', 'overrides',
]);
export const G4_DIR = 'verification/g4';
export const G4_TYPESCRIPT_5_9_3_SHA256 = '8b71c5d742379b8e1f1c8689102074e9da7359d1dee11a2bf8422486097af9e7';
export const G4_PINNED_PACKAGE_JSON_SHA256 = '9ed3c7bf4e3c125f4495169ef251b215ea28ef3d97828a13e008a006aa743ecb';
export const G4_PINNED_PACKAGE_LOCK_SHA256 = 'c694ed58401c2708e9c2dfd7732c8d379915b0d3d841faf08019f7389fca8e5c';
export const G4_PINS_JSON_SHA256 = '5f5922b280a7b2aec4fccb44d0bbf4d01a403f11c7dad2175a62b2f07895d2d0';
export const ENGINE_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function fileSha256(abs) {
  return sha256Hex(readFileSync(abs));
}

export function gitShowSha256(root, rel) {
  const r = spawnSync('git', ['-C', root, 'show', `HEAD:${rel}`], { encoding: 'buffer' });
  if (r.status !== 0) return null;
  return sha256Hex(r.stdout);
}

export function parseG4Verdicts(text) {
  const raw = String(text);
  const lines = raw.replace(/^\uFEFF/, '').split(/\r?\n/);
  let fence = null;
  let inComment = false;
  let inPre = false;
  let unclosedFence = false;
  const topPass = [];
  const topOther = [];
  const hidden = [];
  const failConj = [];
  const cf = /\p{Cf}/u.test(raw);
  const divHidden = /<div\s+hidden/i.test(raw);
  const linkRef = /\[\/\/\]:\s*#/.test(raw);
  // G-44b (HoQ a43a432c): content inside these blocks may not carry the top-level PASS.
  const BLOCK_OPEN = /<(details|style|script|template|textarea|noscript)\b/gi;
  const BLOCK_CLOSE = /<\/(details|style|script|template|textarea|noscript)\s*>/gi;
  let blockDepth = 0;
  // G-44b: FAIL lexicon and label set for the contradicting-line check.
  const FAIL_WORD = /\bFAIL\w*|\bREJECT\w*|\bNOT\s+PASS|\bNO-PASS\b|\bDENIED\b|\bBLOCKED\b|\u2717/i;
  const FAIL_LABEL = /verdict|result|status|outcome|conclusion|decision|assessment|finding/i;
  // G-44b residual (HoQ 4c7adda0/f575fe1f §3.2): unlabelled prose that negates the verdict is red too.
  // Case-insensitive: "does/did not pass", "failed", "fails". Upper case only: NOT PASS, NO-PASS, DENIED,
  // BLOCKED (so ordinary prose such as "not treated as blocking" stays green).
  const UNLABELLED_FAIL_I = /\b(?:does|did)\s+not\s+pass\b|\bfail(?:ed|s)\b/i;
  const UNLABELLED_FAIL_U = /\bNOT\s+PASS\b|\bNO-PASS\b|\bDENIED\b|\bBLOCKED\b|\u2717/;

  const applyHtml = (vis, startComment, startPre) => {
    let inC = startComment, inP = startPre;
    const hid = new Uint8Array(vis.length);
    let i = 0;
    const mark = (from, to) => { for (let k = from; k < to; k++) hid[k] = 1; };
    while (i < vis.length) {
      if (inC) {
        const end = vis.indexOf('-->', i);
        if (end === -1) { mark(i, vis.length); return { inComment: true, inPre: inP, hid }; }
        mark(i, end + 3); i = end + 3; inC = false; continue;
      }
      if (inP) {
        const low = vis.toLowerCase();
        const end = low.indexOf('</pre>', i);
        if (end === -1) { mark(i, vis.length); return { inComment: inC, inPre: true, hid }; }
        mark(i, end + 6); i = end + 6; inP = false; continue;
      }
      const cmt = vis.indexOf('<!--', i);
      const pre = vis.toLowerCase().indexOf('<pre', i);
      let next = -1, kind = null;
      if (cmt !== -1 && (pre === -1 || cmt < pre)) { next = cmt; kind = 'c'; }
      else if (pre !== -1) { next = pre; kind = 'p'; }
      if (next === -1) break;
      if (kind === 'c') { inC = true; i = next; continue; }
      inP = true; i = next; continue;
    }
    return { inComment: inC, inPre: inP, hid };
  };

  for (const line of lines) {
    const vis = line.replace(/^\uFEFF/, '');
    const fenceTry = /^(?:\s{0,3})(`{3,}|~{3,})(.*)$/.exec(vis);
    let isFenceMarker = false;
    if (!inComment && !inPre && fenceTry) {
      const marker = fenceTry[1];
      const rest = fenceTry[2];
      if (!fence) {
        fence = { ch: marker[0], len: marker.length };
        isFenceMarker = true;
      } else if (marker[0] === fence.ch && marker.length >= fence.len && /^\s*$/.test(rest)) {
        fence = null;
        isFenceMarker = true;
      }
    }
    const html = applyHtml(vis, inComment, inPre);
    inComment = html.inComment;
    inPre = html.inPre;
    const htmlHidden = html.hid.length > 0 && html.hid.every((x) => x === 1);
    const htmlPartial = html.hid.length > 0 && html.hid.some((x) => x === 1);
    const inIndented = !fence && !isFenceMarker && /^(?:    |\t)/.test(vis);
    const inQuote = !fence && !isFenceMarker && /^\s{0,3}>/.test(vis);
    const opens = (vis.match(BLOCK_OPEN) || []).length;
    const closes = (vis.match(BLOCK_CLOSE) || []).length;
    const inBlock = !fence && !isFenceMarker && (blockDepth > 0 || opens > 0);
    blockDepth = Math.max(0, blockDepth + opens - closes);
    const codeOrHtmlHidden = !!(fence || isFenceMarker || htmlHidden || (inComment || inPre || htmlPartial) && htmlPartial);
    const lineHidden = !!(codeOrHtmlHidden || inIndented || inQuote || inBlock);

    const stripped = vis.replace(/^(?:    |\t)+/, '').replace(/^(?:\s{0,3}>\s?)+/, '');
    const isDirective = /^\s*verdict\s*:/i.test(stripped);
    // G-44b: blockquoted and indented lines render visibly, so they count for the FAIL check; only fenced
    // code and HTML comment / <pre> content is exempt.
    if (!codeOrHtmlHidden && ((FAIL_WORD.test(vis) && FAIL_LABEL.test(vis)) || UNLABELLED_FAIL_I.test(vis) || UNLABELLED_FAIL_U.test(vis))) failConj.push(line);
    if (isDirective) {
      if (!lineHidden && /^VERDICT:\s+PASS\s*$/.test(stripped)) topPass.push(line);
      else if (!lineHidden) topOther.push(line);
      else hidden.push(line);
    }
  }
  if (fence) unclosedFence = true;
  return { topPass, topOther, hidden, failConj, unclosedFence, cf, divHidden, linkRef };
}

export function parseG4File(text, path = 'g4.md') {
  const issues = [];
  const pkg = /Package:\s*`([^@`\s]+)@([^`]+)`/.exec(text);
  const pkgSha = /package\.json sha256 `([0-9a-f]{64})`/.exec(text);
  const lockSha = /package-lock\.json sha256 `([0-9a-f]{64})`/.exec(text);
  const prov = /provenance is (ABSENT|PRESENT)/i.exec(text);
  if (!pkg) issues.push(`${path}:1: b8-g4 G4 file does not name a Package name@version`);
  if (!pkgSha) issues.push(`${path}:1: b8-g4 G4 file does not name a package.json sha256`);
  if (!lockSha) issues.push(`${path}:1: b8-g4 G4 file does not name a package-lock.json sha256`);
  if (!prov) issues.push(`${path}:1: b8-g4 G4 file does not record provenance present/absent (condition c)`);
  const { topPass, topOther, hidden, failConj, unclosedFence, cf, divHidden, linkRef } = parseG4Verdicts(text);
  if (cf) issues.push(`${path}:1: b8-g4 G4 file contains a Unicode Cf character`);
  if (divHidden) issues.push(`${path}:1: b8-g4 G4 file contains a hidden <div hidden`);
  if (linkRef) issues.push(`${path}:1: b8-g4 G4 file contains a link-reference comment`);
  if (unclosedFence) issues.push(`${path}:1: b8-g4 G4 file has an unclosed code fence`);
  const loneFailVerdict = topPass.length === 0 && topOther.length === 1 && hidden.length === 0
    && failConj.length >= 1 && /^VERDICT:\s+FAIL\s*$/i.test(topOther[0].trim());
  if (failConj.length && !loneFailVerdict) {
    issues.push(`${path}:1: b8-g4 G4 file has a contradicting FAIL/result/status line`);
  }
  const other = [...topOther, ...hidden];
  let pass = false;
  let verdict = null;
  const clean = !cf && !divHidden && !linkRef && !unclosedFence && (failConj.length === 0 || loneFailVerdict);
  if (topPass.length === 1 && other.length === 0 && !cf && !divHidden && !linkRef && !unclosedFence && failConj.length === 0) {
    pass = true;
    verdict = 'VERDICT: PASS';
  } else if (topPass.length === 0 && other.length === 0 && failConj.length === 0 && !unclosedFence && !cf && !divHidden && !linkRef) {
    issues.push(`${path}:1: b8-g4 G4 file is missing a VERDICT line`);
  } else if (topPass.length === 0 && topOther.length === 1 && hidden.length === 0 && !unclosedFence && !cf && !divHidden && !linkRef && (failConj.length === 0 || loneFailVerdict)) {
    issues.push(`${path}:1: b8-g4 G4 file VERDICT is not PASS (${topOther[0].trim()})`);
    verdict = topOther[0].trim();
  } else if (!(topPass.length === 1 && other.length === 0 && !cf && !divHidden && !linkRef && !unclosedFence && failConj.length === 0)) {
    if (!issues.some((x) => /Unicode Cf|hidden <div|link-reference|unclosed code fence|contradicting FAIL/.test(x))) {
      issues.push(`${path}:1: b8-g4 G4 file verdict is not a single top-level VERDICT: PASS`);
    }
  }
  return {
    path,
    name: pkg ? pkg[1] : null,
    version: pkg ? pkg[2] : null,
    id: pkg ? `${pkg[1]}@${pkg[2]}` : null,
    packageJsonSha256: pkgSha ? pkgSha[1] : null,
    packageLockSha256: lockSha ? lockSha[1] : null,
    provenance: prov ? prov[1].toUpperCase() : null,
    pass,
    verdict,
    issues,
  };
}

export function loadG4Files(root) {
  const dir = join(root, G4_DIR);
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith('.md')) continue;
    const rel = `${G4_DIR}/${name}`;
    out.push(parseG4File(readFileSync(join(root, rel), 'utf8'), rel));
  }
  return out;
}

export const G4_PINS_REL = `${G4_DIR}/G4-PINS.json`;

export function loadG4Pins(root) {
  const rel = G4_PINS_REL;
  const abs = join(root, rel);
  const issues = [];
  if (!existsSync(abs)) {
    return { pins: [], issues: [`${rel}:1: b8-g4 missing ${rel}`], byFile: new Map() };
  }
  let data;
  try { data = JSON.parse(readFileSync(abs, 'utf8')); }
  catch (e) { return { pins: [], issues: [`${rel}:1: b8-g4 unreadable G4-PINS.json (${e.message})`], byFile: new Map() }; }
  const list = Array.isArray(data) ? data : (data && data.files);
  if (!Array.isArray(list)) {
    return { pins: [], issues: [`${rel}:1: b8-g4 G4-PINS.json must be an array of {file, sha256} or {files: [...]}`], byFile: new Map() };
  }
  const pins = [];
  const byFile = new Map();
  for (const ent of list) {
    if (!ent || typeof ent.file !== 'string' || typeof ent.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(ent.sha256)) {
      issues.push(`${rel}:1: b8-g4 pin entry is not {file, sha256 with a 64-char hex digest}`);
      continue;
    }
    if (byFile.has(ent.file)) issues.push(`${rel}:1: b8-g4 duplicate pin for ${ent.file}`);
    pins.push(ent);
    byFile.set(ent.file, ent.sha256);
  }
  return { pins, issues, byFile };
}

export function writeG4PinsForTree(dir) {
  const g4dir = join(dir, G4_DIR);
  const files = [];
  if (existsSync(g4dir)) {
    for (const name of readdirSync(g4dir).sort()) {
      if (!name.endsWith('.md')) continue;
      const rel = `${G4_DIR}/${name}`;
      files.push({ file: rel, sha256: fileSha256(join(dir, rel)) });
    }
  }
  const p = join(dir, G4_PINS_REL);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify({ files }, null, 2) + '\n');
}

export function coveringG4Markdown({ name, version, packageJsonSha256, packageLockSha256, provenance = 'ABSENT' }) {
  return [
    `# G4 dependency verdict: ${name}@${version}`,
    '',
    `- Package: \`${name}@${version}\``,
    `- package.json sha256 \`${packageJsonSha256}\``,
    `- package-lock.json sha256 \`${packageLockSha256}\``,
    '',
    `VERDICT: PASS`,
    '',
    `npm provenance is ${provenance} for this version.`,
    '',
  ].join('\n');
}

function packageJsonPaths(root) {
  const out = ['package.json'];
  const dir = join(root, 'packages');
  if (existsSync(dir)) {
    for (const name of readdirSync(dir)) {
      const p = `packages/${name}/package.json`;
      if (existsSync(join(root, p))) out.push(p);
    }
  }
  return out;
}

function depsEmpty(deps) {
  return deps !== undefined && typeof deps === 'object' && !Array.isArray(deps) && Object.keys(deps).length === 0;
}

function isExactPin(v) {
  return typeof v === 'string' && EXACT_VERSION.test(v);
}

function fieldEmptyOrAbsent(pkg, key) {
  if (!(key in pkg) || pkg[key] === undefined) return true;
  return depsEmpty(pkg[key]);
}

export function scanManifest(pkg, { path = 'package.json', isRoot = false } = {}) {
  const hits = [];
  if (!pkg || typeof pkg !== 'object') {
    hits.push(`${path}:1: b8-dependencies unreadable package.json`);
    return hits;
  }
  if (!depsEmpty(pkg.dependencies ?? {})) {
    // missing key is treated as empty (zero runtime deps); a non-empty object is red
    if (pkg.dependencies === undefined) {
      // allowed: absent === empty. We still prefer an explicit {} but do not fail closed on absence
      // if the object would be empty. (Current repo writes explicit {}. A present non-object is red.)
    } else if (!depsEmpty(pkg.dependencies)) {
      hits.push(`${path}:1: b8-dependencies 'dependencies' must be {} (R-1); found ${JSON.stringify(pkg.dependencies)}`);
    }
  }
  if (pkg.dependencies === null) {
    hits.push(`${path}:1: b8-dependencies 'dependencies' must be {} (R-1); found null`);
  }
  const dev = pkg.devDependencies ?? {};
  if (typeof dev !== 'object' || Array.isArray(dev) || dev === null) {
    hits.push(`${path}:1: b8-dependencies 'devDependencies' must be an object of exact pins`);
  } else {
    for (const [name, ver] of Object.entries(dev)) {
      if (!isExactPin(ver)) hits.push(`${path}:1: b8-dependencies devDependency '${name}' is not an exact pin (${JSON.stringify(ver)})`);
    }
  }
  for (const key of EMPTY_OR_ABSENT_FIELDS) {
    if (!fieldEmptyOrAbsent(pkg, key)) {
      hits.push(`${path}:1: b8-dependencies '${key}' must be {} or absent; found ${JSON.stringify(pkg[key])}`);
    }
  }
  return hits;
}

export function scanLockfile(root, rootPkg) {
  const hits = [];
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(lockPath)) {
    hits.push('package-lock.json:1: b8-dependencies missing package-lock.json');
    return hits;
  }
  let lock;
  try { lock = JSON.parse(readFileSync(lockPath, 'utf8')); }
  catch (e) { return [`package-lock.json:1: b8-dependencies unreadable package-lock.json (${e.message})`]; }
  const rootEntry = (lock.packages && lock.packages['']) || {};
  if (rootEntry.dependencies && Object.keys(rootEntry.dependencies).length) {
    hits.push(`package-lock.json:1: b8-dependencies lockfile records runtime dependencies ${JSON.stringify(rootEntry.dependencies)}`);
  }
  const pkgDev = rootPkg?.devDependencies ?? {};
  const lockDev = rootEntry.devDependencies ?? {};
  const pkgKeys = Object.keys(pkgDev).sort();
  const lockKeys = Object.keys(lockDev).sort();
  if (JSON.stringify(pkgKeys) !== JSON.stringify(lockKeys)) {
    hits.push(`package-lock.json:1: b8-dependencies lockfile devDependencies {${lockKeys.join(', ')}} do not match package.json {${pkgKeys.join(', ')}}`);
  }
  for (const [name, ver] of Object.entries(pkgDev)) {
    if (lockDev[name] && lockDev[name] !== ver) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile pins '${name}' at ${lockDev[name]} but package.json has ${ver}`);
    }
  }
  const pkgs = lock.packages ?? {};
  for (const [name, ver] of Object.entries(pkgDev)) {
    const rel = `node_modules/${name}`;
    if (!pkgs[rel]) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile is missing entry '${rel}'`);
      continue;
    }
    if (pkgs[rel].version !== ver) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' version ${JSON.stringify(pkgs[rel].version)} does not equal the pin ${ver}`);
    }
  }
  for (const [rel, ent] of Object.entries(pkgs)) {
    if (rel === '') continue;
    if (!ent || typeof ent !== 'object') {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is unreadable`);
      continue;
    }
    if (ent.link) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is a link entry`);
    }
    if (ent.dev !== true && rel.startsWith('node_modules/') && !ent.devOptional && !ent.link) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is a runtime dependency`);
    }
    const integrity = ent.integrity;
    if (typeof integrity !== 'string' || !integrity.startsWith('sha512-')) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' integrity must be sha512 (including devOptional entries); found ${JSON.stringify(integrity)}`);
    }
    const resolved = ent.resolved;
    if (typeof resolved !== 'string' || !resolved.startsWith(REGISTRY_RESOLVED_PREFIX)) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' resolved must start with ${REGISTRY_RESOLVED_PREFIX}; found ${JSON.stringify(resolved)}`);
    }
  }
  return hits;
}

// G-44a (HoQ a43a432c): the gate compares against `pinsRoot` (default ENGINE_ROOT) so the self-test can
// drive the real call path (scanRoot -> scanG4 -> checkG4PinsFileSha) on a scratch root and prove that
// removing the call site or breaking the gate turns the self-test red.
export function checkG4PinsFileSha(root, hits = [], { force = false, pinsRoot = ENGINE_ROOT } = {}) {
  if (!force && resolve(root) !== resolve(pinsRoot)) return hits;
  const pinsAbs = join(root, G4_PINS_REL);
  if (!existsSync(pinsAbs)) {
    hits.push(`${G4_PINS_REL}:1: b8-g4 G4-PINS.json is missing`);
    return hits;
  }
  const psha = fileSha256(pinsAbs);
  if (psha !== G4_PINS_JSON_SHA256) {
    hits.push(`${G4_PINS_REL}:1: b8-g4 G4-PINS.json sha256 ${psha} does not match the pinned digest ${G4_PINS_JSON_SHA256}`);
  }
  return hits;
}

export function scanG4(root, rootPkg, { pinsRoot = ENGINE_ROOT } = {}) {
  const hits = [];
  checkG4PinsFileSha(root, hits, { pinsRoot });
  const pins = loadG4Pins(root);
  hits.push(...pins.issues);
  const g4s = loadG4Files(root);
  const seen = new Set();
  for (const g of g4s) {
    hits.push(...g.issues);
    const abs = join(root, g.path);
    const sha = existsSync(abs) ? fileSha256(abs) : null;
    const pinned = pins.byFile.get(g.path);
    if (!pinned) hits.push(`${g.path}:1: b8-g4 G4 file is not listed in ${G4_PINS_REL}`);
    else if (sha && pinned !== sha) hits.push(`${g.path}:1: b8-g4 sha256 ${sha} does not match the pin ${pinned}`);
    seen.add(g.path);
  }
  for (const file of pins.byFile.keys()) {
    if (!seen.has(file)) hits.push(`${file}:1: b8-g4 pinned G4 file is missing`);
  }
  const pinOk = (g) => pins.byFile.get(g.path) && existsSync(join(root, g.path)) && pins.byFile.get(g.path) === fileSha256(join(root, g.path));
  const usable = g4s.filter((g) => g.id && g.packageJsonSha256 && g.packageLockSha256 && g.provenance && g.pass && g.issues.length === 0 && pinOk(g));
  const byId = new Map(usable.map((g) => [g.id, g]));
  const dev = (rootPkg && rootPkg.devDependencies && typeof rootPkg.devDependencies === 'object') ? rootPkg.devDependencies : {};
  for (const [name, ver] of Object.entries(dev)) {
    const id = `${name}@${ver}`;
    if (!byId.has(id)) hits.push(`${G4_DIR}:1: b8-g4 no G4 PASS file covers devDependency ${id}`);
  }
  for (const g of g4s) {
    if (g.name && g.version && Object.prototype.hasOwnProperty.call(dev, g.name) && String(dev[g.name]) !== g.version) {
      hits.push(`${g.path}:1: b8-g4 G4 file Package version '${g.version}' does not match the manifest pin '${dev[g.name]}'`);
    }
  }
  const pkgPath = join(root, 'package.json');
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(pkgPath) || !existsSync(lockPath)) return hits;
  const workPkg = fileSha256(pkgPath);
  const workLock = fileSha256(lockPath);
  const headPkg = gitShowSha256(root, 'package.json');
  const headLock = gitShowSha256(root, 'package-lock.json');
  const namedPkg = new Set(usable.map((g) => g.packageJsonSha256));
  const namedLock = new Set(usable.map((g) => g.packageLockSha256));
  const check = (label, sha, named, rel) => {
    if (!sha) return;
    if (![...named].some((h) => h === sha)) {
      hits.push(`${rel}:1: b8-g4 ${label} sha256 ${sha} is not named in a covering G4 file (manifest change without a matching new G4 file)`);
    }
  };
  if (usable.length) {
    check('worktree package.json', workPkg, namedPkg, 'package.json');
    check('worktree package-lock.json', workLock, namedLock, 'package-lock.json');
    if (headPkg) check('HEAD package.json', headPkg, namedPkg, 'package.json');
    if (headLock) check('HEAD package-lock.json', headLock, namedLock, 'package-lock.json');
  } else if (Object.keys(dev).length) {
    hits.push(`${G4_DIR}:1: b8-g4 no usable G4 PASS file is present for the current devDependencies`);
  }
  return hits;
}

export function scanRoot(root, { pinsRoot = ENGINE_ROOT } = {}) {
  const hits = [];
  let rootPkg = null;
  for (const rel of packageJsonPaths(root)) {
    const abs = join(root, rel);
    try {
      const pkg = JSON.parse(readFileSync(abs, 'utf8'));
      if (rel === 'package.json') rootPkg = pkg;
      hits.push(...scanManifest(pkg, { path: rel, isRoot: rel === 'package.json' }));
    } catch (e) {
      hits.push(`${rel}:1: b8-dependencies unreadable package.json (${e.message})`);
    }
  }
  hits.push(...scanLockfile(root, rootPkg));
  hits.push(...scanG4(root, rootPkg, { pinsRoot }));
  return hits;
}

const GOOD_PKG = {
  name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module',
  dependencies: {}, devDependencies: { typescript: '5.9.3' },
};
const GOOD_LOCK = {
  lockfileVersion: 3, name: 'open-rng-engine', packages: {
    '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } },
    'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' },
  },
};

// G-44b (HoQ a43a432c): [build(mdPass) -> G4 text, expected reason].
const G44B_FAIL = /contradicting FAIL\/result\/status line/;
const G44B_HIDDEN_PASS = /not a single top-level VERDICT: PASS/;
const G44B_REWORD = (md) => md.replace('VERDICT: PASS', 'The reviewer rejected this dependency.');
export const G44B_SPECIALS = {
  'g44b-bq2-fail': [(md) => md + '\n> > VERDICT: FAIL\n', G44B_FAIL],
  'g44b-bq-status-fail': [(md) => md + '\n> Status: FAIL\n', G44B_FAIL],
  'g44b-bq-prose-fail': [(md) => md + '\n> The verdict is FAIL.\n', G44B_FAIL],
  'g44b-indented-fail': [(md) => md + '\n    Result: FAIL\n', G44B_FAIL],
  'g44b-outcome-fail': [(md) => md + '\nOutcome: FAIL\n', G44B_FAIL],
  'g44b-table-outcome-fail': [(md) => md + '\n| Outcome | FAIL |\n', G44B_FAIL],
  'g44b-failed-word': [(md) => md + '\n**Verdict** FAILED\n', G44B_FAIL],
  'g44b-rejected-word': [(md) => md + '\nStatus: REJECTED\n', G44B_FAIL],
  'g44b-details-pass': [(md) => G44B_REWORD(md) + '\n<details>\nVERDICT: PASS\n</details>\n', G44B_HIDDEN_PASS],
  'g44b-style-pass': [(md) => G44B_REWORD(md) + '\n<style>\nVERDICT: PASS\n</style>\n', G44B_HIDDEN_PASS],
  'g44b-script-pass': [(md) => G44B_REWORD(md) + '\n<script>\nVERDICT: PASS\n</script>\n', G44B_HIDDEN_PASS],
  'g44b-template-pass': [(md) => G44B_REWORD(md) + '\n<template>\nVERDICT: PASS\n</template>\n', G44B_HIDDEN_PASS],
  // G-44b residual (HoQ 4c7adda0/f575fe1f §3.2): unlabelled prose and labels/words outside the old set.
  'g44b-prose-does-not-pass': [(md) => md + '\nThe dependency does NOT PASS.\n', G44B_FAIL],
  'g44b-prose-did-not-pass': [(md) => md + '\nIt did not pass the review.\n', G44B_FAIL],
  'g44b-prose-failed': [(md) => md + '\nThe review failed.\n', G44B_FAIL],
  'g44b-prose-fails': [(md) => md + '\nThis dependency fails review.\n', G44B_FAIL],
  'g44b-assessment-fail': [(md) => md + '\nAssessment: FAIL\n', G44B_FAIL],
  'g44b-finding-fail': [(md) => md + '\nFinding: FAIL\n', G44B_FAIL],
  'g44b-result-denied': [(md) => md + '\nResult: DENIED\n', G44B_FAIL],
  'g44b-result-blocked': [(md) => md + '\nResult: BLOCKED\n', G44B_FAIL],
  'g44b-bare-denied': [(md) => md + '\nDENIED\n', G44B_FAIL],
  'g44b-bare-blocked': [(md) => md + '\nBLOCKED by HoQ.\n', G44B_FAIL],
  'g44b-no-pass': [(md) => md + '\nResult: NO-PASS\n', G44B_FAIL],
  'g44b-cross-mark': [(md) => md + '\nResult: \u2717\n', G44B_FAIL],
};

export const BAD_FIXTURES = {
  'runtime-dep': {
    pkg: { ...GOOD_PKG, dependencies: { leftpad: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /'dependencies' must be \{\}/,
  },
  'unpinned-devdep': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '^5.9.3' } },
    lock: { ...GOOD_LOCK, packages: { ...GOOD_LOCK.packages, '': { ...GOOD_LOCK.packages[''], devDependencies: { typescript: '^5.9.3' } } } },
    reason: /not an exact pin/,
  },
  'workspace-runtime-dep': {
    pkg: GOOD_PKG,
    extra: { 'packages/mapping/package.json': { name: '@open-rng-engine/mapping', version: '0.0.0', private: true, type: 'module', dependencies: { leftpad: '1.0.0' } } },
    lock: GOOD_LOCK,
    reason: /packages\/mapping\/package.json:1: b8-dependencies 'dependencies' must be \{\}/,
  },
  'lockfile-mismatch': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '5.9.3', unusedcheck: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /lockfile devDependencies/,
  },
  'pin-partial-x': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '5.9.x' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.x' } }, 'node_modules/typescript': { version: '5.9.x', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'pin-latest': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: 'latest' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: 'latest' } }, 'node_modules/typescript': { version: 'latest', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'pin-equals': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '=5.9.3' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '=5.9.3' } }, 'node_modules/typescript': { version: '=5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'optional-deps': {
    pkg: { ...GOOD_PKG, optionalDependencies: { leftpad: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /'optionalDependencies' must be \{\} or absent/,
  },
  'peer-deps': {
    pkg: { ...GOOD_PKG, peerDependencies: { typescript: '5.9.3' } },
    lock: GOOD_LOCK,
    reason: /'peerDependencies' must be \{\} or absent/,
  },
  'bundle-deps': {
    pkg: { ...GOOD_PKG, bundleDependencies: ['typescript'] },
    lock: GOOD_LOCK,
    reason: /'bundleDependencies' must be \{\} or absent/,
  },
  'bundled-deps': {
    pkg: { ...GOOD_PKG, bundledDependencies: ['typescript'] },
    lock: GOOD_LOCK,
    reason: /'bundledDependencies' must be \{\} or absent/,
  },
  'overrides': {
    pkg: { ...GOOD_PKG, overrides: { typescript: '5.9.3' } },
    lock: GOOD_LOCK,
    reason: /'overrides' must be \{\} or absent/,
  },
  'lock-version-mismatch': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.8.0', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.8.0.tgz' } } },
    reason: /version .* does not equal the pin/,
  },
  'lock-resolved-non-registry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://example.com/typescript-5.9.3.tgz' } } },
    reason: /resolved must start with https:\/\/registry\.npmjs\.org\//,
  },
  'lock-integrity-sha1': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha1-deadbeef', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /integrity must be sha512/,
  },
  'lock-devOptional-no-integrity': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' }, 'node_modules/optional-tool': { version: '1.0.0', devOptional: true, resolved: 'https://registry.npmjs.org/optional-tool/-/optional-tool-1.0.0.tgz' } } },
    reason: /integrity must be sha512 \(including devOptional entries\)/,
  },
  'lock-missing-entry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } } } },
    reason: /missing entry 'node_modules\/typescript'/,
  },
  'lock-link-entry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' }, 'node_modules/linked': { link: true, resolved: '../linked' } } },
    reason: /is a link entry/,
  },
  'mutated-manifest-no-g4': {
    pkg: { ...GOOD_PKG, description: 'mutated' },
    lock: GOOD_LOCK,
    reason: /manifest change without a matching new G4 file/,
    g4From: 'control',
  },
  'fail-verdict': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /VERDICT is not PASS/,
    g4Special: 'fail-verdict',
  },
  'edited-content': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /does not match the pin/,
    g4Special: 'edited-content',
  },
  'forged-4-line': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /missing a VERDICT line/,
    g4Special: 'forged-4-line',
  },
  'wrong-version': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /Package version .* does not match the manifest pin/,
    g4Special: 'wrong-version',
  },
  'unpinned-extra-file': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /is not listed in/,
    g4Special: 'unpinned-extra-file',
  },
  'pin-list-mismatch': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /does not match the pin/,
    g4Special: 'pin-list-mismatch',
  },
  'runtime-lock-entry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { ...GOOD_LOCK.packages, 'node_modules/leftpad': { version: '1.0.0', integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/leftpad/-/leftpad-1.0.0.tgz' } } },
    reason: /is a runtime dependency/,
  },
  'root-entry-runtime-deps': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' }, dependencies: { leftpad: '1.0.0' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /lockfile records runtime dependencies/,
  },
  'lock-root-devdep-version': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.8.0' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /lockfile pins 'typescript' at 5\.8\.0 but package.json has 5\.9\.3/,
  },
  'dependencies-null': {
    pkg: { ...GOOD_PKG, dependencies: null },
    lock: GOOD_LOCK,
    reason: /found null/,
  },
  'g4-coverage': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '5.9.3', leftover: '1.0.0' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: {
      '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3', leftover: '1.0.0' } },
      'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' },
      'node_modules/leftover': { version: '1.0.0', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/leftover/-/leftover-1.0.0.tgz' },
    } },
    reason: /no G4 PASS file covers devDependency leftover@1\.0\.0/,
  },
  'verdict-fail-fenced-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS|contradicting FAIL/,
    g4Special: 'verdict-fail-fenced-pass',
  },
  'blockquoted-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS/,
    g4Special: 'blockquoted-pass',
  },
  'indented-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS/,
    g4Special: 'indented-pass',
  },
  'tilde-fence-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS|unclosed code fence/,
    g4Special: 'tilde-fence-pass',
  },
  'four-backtick-fence-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS/,
    g4Special: 'four-backtick-fence-pass',
  },
  'html-comment-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS/,
    g4Special: 'html-comment-pass',
  },
  'pre-pass': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /not a single top-level VERDICT: PASS/,
    g4Special: 'pre-pass',
  },
  'unclosed-fence': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /unclosed code fence/,
    g4Special: 'unclosed-fence',
  },
  'table-verdict-fail': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /contradicting FAIL\/result\/status line/,
    g4Special: 'table-verdict-fail',
  },
  'bold-verdict-fail': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /contradicting FAIL\/result\/status line/,
    g4Special: 'bold-verdict-fail',
  },
  'emdash-verdict-fail': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /contradicting FAIL\/result\/status line/,
    g4Special: 'emdash-verdict-fail',
  },
  'result-fail': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /contradicting FAIL\/result\/status line/,
    g4Special: 'result-fail',
  },
  'div-hidden': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /hidden <div hidden/,
    g4Special: 'div-hidden',
  },
  'link-ref-comment': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /link-reference comment/,
    g4Special: 'link-ref-comment',
  },
  'unicode-cf': {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: /Unicode Cf character/,
    g4Special: 'unicode-cf',
  },
  // G-44b residual (HoQ a43a432c, section 3): each case is red for the reason given.
  ...Object.fromEntries(Object.keys(G44B_SPECIALS).map((k) => [k, {
    pkg: GOOD_PKG, lock: GOOD_LOCK,
    reason: G44B_SPECIALS[k][1],
    g4Special: k,
  }])),
};

function writeJson(dir, rel, obj) {
  const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

function writeCoveringG4(dir, pkg, lock) {
  writeJson(dir, 'package.json', pkg);
  writeJson(dir, 'package-lock.json', lock);
  const packageJsonSha256 = fileSha256(join(dir, 'package.json'));
  const packageLockSha256 = fileSha256(join(dir, 'package-lock.json'));
  const dev = pkg.devDependencies ?? {};
  const first = Object.entries(dev)[0] || ['typescript', '5.9.3'];
  const md = coveringG4Markdown({ name: first[0], version: first[1], packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
  const p = join(dir, G4_DIR, 'g4-typescript-5.9.3.md');
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, md);
  writeG4PinsForTree(dir);
}

export function writeSpecialG4(d, name, pkg, lock) {
  const packageJsonSha256 = fileSha256(join(d, 'package.json'));
  const packageLockSha256 = fileSha256(join(d, 'package-lock.json'));
  const mdPass = coveringG4Markdown({ name: 'typescript', version: '5.9.3', packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
  const g4path = join(d, G4_DIR, 'g4-typescript-5.9.3.md');
  mkdirSync(dirname(g4path), { recursive: true });
  if (name === 'fail-verdict') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', 'VERDICT: FAIL'));
    writeG4PinsForTree(d);
  } else if (name === 'edited-content') {
    writeFileSync(g4path, mdPass);
    writeG4PinsForTree(d);
    writeFileSync(g4path, mdPass + '\n# edited\n');
  } else if (name === 'forged-4-line') {
    const forged = [
      `Package: \`typescript@5.9.3\``,
      `package.json sha256 \`${packageJsonSha256}\``,
      `package-lock.json sha256 \`${packageLockSha256}\``,
      'provenance is ABSENT',
      '',
    ].join('\n');
    writeFileSync(g4path, forged);
    writeG4PinsForTree(d);
  } else if (name === 'wrong-version') {
    writeFileSync(g4path, mdPass);
    const extra = coveringG4Markdown({ name: 'typescript', version: '5.9.2', packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
    writeFileSync(join(d, G4_DIR, 'g4-typescript-5.9.2.md'), extra);
    writeG4PinsForTree(d);
  } else if (name === 'unpinned-extra-file') {
    writeFileSync(g4path, mdPass);
    writeG4PinsForTree(d);
    writeFileSync(join(d, G4_DIR, 'g4-extra.md'), mdPass);
  } else if (name === 'pin-list-mismatch') {
    writeFileSync(g4path, mdPass);
    writeG4PinsForTree(d);
    const pinsPath = join(d, G4_PINS_REL);
    const pins = JSON.parse(readFileSync(pinsPath, 'utf8'));
    pins.files[0].sha256 = '0'.repeat(64);
    writeFileSync(pinsPath, JSON.stringify(pins, null, 2) + '\n');
  } else if (name === 'verdict-fail-fenced-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', 'verdict: FAIL') + '\n```\nVERDICT: PASS\n```\n');
    writeG4PinsForTree(d);
  } else if (name === 'blockquoted-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '> VERDICT: PASS'));
    writeG4PinsForTree(d);
  } else if (name === 'indented-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '    VERDICT: PASS'));
    writeG4PinsForTree(d);
  } else if (name === 'tilde-fence-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '~~~\nVERDICT: PASS\n~~~'));
    writeG4PinsForTree(d);
  } else if (name === 'four-backtick-fence-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '````\n```\nVERDICT: PASS\n```\n````'));
    writeG4PinsForTree(d);
  } else if (name === 'html-comment-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '<!--\nVERDICT: PASS\n-->'));
    writeG4PinsForTree(d);
  } else if (name === 'pre-pass') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', '<pre>\nVERDICT: PASS\n</pre>'));
    writeG4PinsForTree(d);
  } else if (name === 'unclosed-fence') {
    writeFileSync(g4path, mdPass.replace('VERDICT: PASS', 'VERDICT: PASS\n```\nhidden'));
    writeG4PinsForTree(d);
  } else if (name === 'table-verdict-fail') {
    writeFileSync(g4path, mdPass + '\n| VERDICT | FAIL |\n');
    writeG4PinsForTree(d);
  } else if (name === 'bold-verdict-fail') {
    writeFileSync(g4path, mdPass + '\n**VERDICT:** FAIL\n');
    writeG4PinsForTree(d);
  } else if (name === 'emdash-verdict-fail') {
    writeFileSync(g4path, mdPass + '\nVerdict \u2014 FAIL\n');
    writeG4PinsForTree(d);
  } else if (name === 'result-fail') {
    writeFileSync(g4path, mdPass + '\nResult: FAIL\n');
    writeG4PinsForTree(d);
  } else if (name === 'div-hidden') {
    writeFileSync(g4path, mdPass + '\n<div hidden>VERDICT: FAIL</div>\n');
    writeG4PinsForTree(d);
  } else if (name === 'link-ref-comment') {
    writeFileSync(g4path, mdPass + '\n[//]: # (VERDICT: FAIL)\n');
    writeG4PinsForTree(d);
  } else if (Object.hasOwn(G44B_SPECIALS, name)) {
    writeFileSync(g4path, G44B_SPECIALS[name][0](mdPass));
    writeG4PinsForTree(d);
  } else if (name === 'unicode-cf') {
    writeFileSync(g4path, mdPass + '\nVER' + '\u200B' + 'DICT: FAIL\n');
    writeG4PinsForTree(d);
  } else {
    writeFileSync(g4path, mdPass);
    writeG4PinsForTree(d);
  }
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'b8-'));
  try {
    const ctl = join(base, 'control');
    writeCoveringG4(ctl, GOOD_PKG, GOOD_LOCK);
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    const pinsNeedle = 'if (psha !== G4_PINS_JSON_SHA256)';
    const toolSrc = readFileSync(fileURLToPath(import.meta.url), 'utf8');
    if (!toolSrc.includes(pinsNeedle)) fails.push('G-44a: pins-sha comparison needle missing from scanG4/checkG4PinsFileSha');
    // G-44a: through the full scan path with the scratch root treated as the engine root, a non-official
    // G4-PINS.json must be red (kills call-site-removed and gate-always-skips), and the scratch root
    // under the default gate must not run the pins check (kills gate-always-runs).
    const viaScan = scanRoot(ctl, { pinsRoot: ctl });
    if (!viaScan.some((h) => /does not match the pinned digest/.test(h))) {
      fails.push(`G-44a: scanRoot(pinsRoot=root) must reach checkG4PinsFileSha and red a non-official G4-PINS.json:\n${viaScan.join('\n')}`);
    }
    if (scanRoot(ctl).some((h) => /does not match the pinned digest/.test(h))) {
      fails.push('G-44a: default gate ran the pins check on a scratch root');
    }
    if (fileSha256(join(ENGINE_ROOT, G4_PINS_REL)) !== '5f5922b280a7b2aec4fccb44d0bbf4d01a403f11c7dad2175a62b2f07895d2d0') {
      fails.push('G-44a: real G4-PINS.json does not match the self-test digest literal');
    }
    const pinsHits = checkG4PinsFileSha(ctl, [], { force: true });
    if (!pinsHits.some((h) => /does not match the pinned digest/.test(h))) {
      fails.push(`G-44a: pins-sha check must red a non-official G4-PINS.json (kills the pins-sha-check-disabled mutant):\n${pinsHits.join('\n')}`);
    }
    const controlG4 = readFileSync(join(ctl, G4_DIR, 'g4-typescript-5.9.3.md'), 'utf8');
    for (const [name, fix] of Object.entries(BAD_FIXTURES)) {
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify(fix.pkg)))));
      writeJson(d, 'package-lock.json', fix.lock);
      if (fix.extra) for (const [rel, obj] of Object.entries(fix.extra)) writeJson(d, rel, obj);
      if (fix.g4Special) {
        writeSpecialG4(d, fix.g4Special, fix.pkg, fix.lock);
      } else if (fix.g4From === 'control') {
        const p = join(d, G4_DIR, 'g4-typescript-5.9.3.md');
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, controlG4);
        writeG4PinsForTree(d);
      } else if (isExactPin(Object.values(fix.pkg.devDependencies ?? {})[0] ?? '') && name !== 'lockfile-mismatch') {
        // Own covering G4 so the fixture is red for its intended reason, not only a missing G4.
        const packageJsonSha256 = fileSha256(join(d, 'package.json'));
        const packageLockSha256 = fileSha256(join(d, 'package-lock.json'));
        const first = Object.entries(fix.pkg.devDependencies)[0];
        const md = coveringG4Markdown({ name: first[0], version: first[1], packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
        const p = join(d, G4_DIR, 'g4-typescript-5.9.3.md');
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, md);
        writeG4PinsForTree(d);
      }
      const hits = scanRoot(d);
      if (!hits.some((h) => fix.reason.test(h))) fails.push(`${name} did not turn B8 red:\n${hits.join('\n')}`);
    }
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`b8 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`b8 self-test: ${Object.keys(BAD_FIXTURES).length} known-bad fixtures red, control green`);
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && here === process.argv[1]) {
  const args = process.argv.slice(2);
  // Evidence-harness preconditions (decision rule v1 FROZEN 5d09c75a, rules 8, 15, 17) ride on this check:ph0
  // step because package.json is frozen; they run only for this repo's own tree, not for scratch roots.
  const ownRoot = join(dirname(here), '..', '..');
  if (args.includes('--self-test')) {
    selfTest();
    const h = await import('../../verification/harness/check.mjs');
    const r = await h.selfTest(ownRoot);
    if (r.fails.length) { console.error(`harness self-test FAILED:\n${r.fails.join('\n')}`); process.exit(1); }
    console.log(`harness self-test: ${r.fixtures.length} fixtures as expected, ${r.mutants.filter((x) => x.status === 'KILLED').length}/${r.mutants.length} mutants killed`);
  } else {
    const root = args.find((a) => !a.startsWith('-')) ?? process.cwd();
    const hits = scanRoot(root);
    if (hits.length) { hits.forEach((h) => console.log(h)); console.log(`b8 dependencies: ${hits.length} finding(s)`); process.exit(1); }
    console.log('b8 dependencies: 0 finding(s)');
    if (resolve(root) === resolve(ownRoot)) {
      const h = await import('../../verification/harness/check.mjs');
      const f = await h.runChecks(ownRoot);
      if (f.length) { f.forEach((x) => console.log(x)); console.log(`harness preconditions: ${f.length} finding(s)`); process.exit(1); }
      console.log('harness preconditions: 0 finding(s)');
      // Readiness is reported, never a PH0 failure; it blocks only the evidence-run entry (evidence-entry.mjs).
      const { harnessReadiness } = await import('../../verification/harness/evidence-entry.mjs');
      const rd = harnessReadiness(ownRoot);
      console.log(`harness readiness: ${rd.ready ? 'READY' : 'NOT-READY'} (rule 8 df fixed ${rd.df.fixed} of ${rd.df.dfNull} df-null entries, ${rd.df.open.length} open; evidence-run entry blocked while open)`);
    }
  }
}
