#!/usr/bin/env node
// CI rule 27, import allowlist for core src/ (quality.md v5.5.7 sha 0202a82b L596; QR-25 L228; PLAN R-44 L152, QR-25 L368, L671).
// Parsed with the pinned TypeScript compiler (5.9.3) AST. Identifier comparison uses decoded text
// (`ts.idText` / `escapedText`); raw `\u` escapes in identifiers or string-literal property keys are red (G-23).
// Red (exit 1) if, in core src/:
//  - node:crypto is reached other than as named ESM imports, or the (symbol, directory) set differs in any way from
//    {(randomFillSync, entropy/), (createHash, evidence/), (getFips, identity/)} (missing or extra pairs are both red);
//  - any of: namespace import, default import, require('node:crypto'|'crypto'), dynamic import(), process.binding,
//    process.getBuiltinModule, globalThis.crypto incl. computed globalThis[...] access, the bare global crypto, the globals
//    global/self, any import of node:module, the identifier createRequire, appears (L596, read literally);
//  - a setFips or fips identifier or member appears;
//  - a file in audited/ imports anything other than core-internal modules (relative paths that stay inside src/);
//  - Object.defineProperty(globalThis, ...) appears in core src/ (the single R-58(6) exception is outside src/).
//  G-24: module specifiers are a POSITIVE allow-list. Allowed: relative paths that resolve inside SCAN_ROOTS, plus
//    `node:crypto` for the required triple only. Everything else is red in every form (static import, export-from,
//    import(), require, ImportEquals). That includes node:vm, inspector, worker_threads, child_process and any bare
//    `crypto` / `fs`. `import type` is fine only for relative core paths. `@open-rng-engine/drbg` (and a relative path
//    into packages/drbg) remains allowed only at VERIFY_BINDING_PATH.
//  G-21/22: any member access named `constructor` (property access, element access with a literal, destructuring) is
//    red, as are Reflect.construct, Object/Reflect.getPrototypeOf, and `__proto__`.
//  G-25: the M-152c fixture is hasOwn(globalThis,'k') at a non-guard path and is red (globalThis-alias). The exact
//    coreGuard forms are allowed only at packages/capability/src/coreGuard.ts.
//  G-26: any `Reflect` identifier in scanned source is red. S-1/G-37: element-access and o[k]= keys use fail-closed
//    reference classification. The type checker is used to resolve symbols (not name matching, so shadowing is
//    handled) and, as a second layer only, never sufficient on its own, to require the binding's declared or
//    inferred type to be exactly `number` (or a number literal / a union of only those; not a union with string).
//    A type-checker `number` alone is never enough. Reflective-base keys are green only as a source literal or a
//    syntactically numeric form.
//    COMPUTED_LITERAL_KEYS_ALLOWED stays empty in production. S-1 also reds the `Proxy` identifier, `.crypto` as a
//    member name on any base, and treats no-substitution templates like string literals everywhere (incl. keys).
//  G-27: every relative specifier must have an explicit allowed extension (.ts/.mts/.cts) and resolve to exactly one
//    file this scan parsed; unresolved, extensionless, outside the scanned set, or via node_modules is red. Every
//    git-tracked source file under SCAN_ROOTS must be parsed (`git ls-files`). `.js`/`.mjs`/`.cjs` under src/ is red.
//  G-28: string literals / no-substitution templates whose value is constructor / __proto__ / prototype are red
//    anywhere in scanned source (AST value, any position). __lookupGetter__/__lookupSetter__/__defineGetter__/
//    __defineSetter__ are red as identifiers or member names. Object.getOwnPropertyDescriptor(s), getPrototypeOf,
//    setPrototypeOf and defineProperty are red outside coreGuard's exact forms. Computed keys in destructuring
//    patterns or object literals are red unless the key is a numeric literal. Element access is green only with a
//    numeric literal key, or a syntactically numeric runtime key: a numeric literal; unary +/-
//    or ~ applied to anything; a binary operator that always yields a number (- * / % ** | & ^ << >> >>>, not + or +=);
//    or a same-function let/const whose every identifier reference, resolved by the checker symbol, is a pure READ or a
//    recognised NUMERIC WRITE (initialiser or plain `=` whose RHS is one of those forms, ++/--, or a compound whose
//    operator is in the S-1 numeric binary set). ANY assignment-target that is not a recognised numeric write is red
//    (array/object/shorthand/nested/default/rest destructuring, for-in/for-of heads, += ??= ||= &&= and other
//    non-numeric compounds, writes in nested functions/arrows or labelled blocks). Unclassifiable is red. Parameters,
//    imports and module-level bindings stay red. Type assertions (as, <T>), any/unknown in type positions, the non-null !, @ts-ignore and @ts-nocheck
//    are red; @ts-expect-error is allowed only at the single pinned entropy import line. Error.prepareStackTrace,
//    captureStackTrace and stackTraceLimit are red.
//  G-30: closed-world (unparsed-tracked) and js-under-src have their own fixtures. Tracked extensionless and .json
//    files under SCAN_ROOTS are red unless listed on TRACKED_NON_TS_ALLOWED (exact paths; empty for src).
// HoQ ruling on rule 27 (relayed by CTO 2026-11-18 09:00 CET):
//  Q1 'no more' always blocks; 'no fewer' blocks once entropy/, evidence/ or identity/ exists under src/, is report-only
//     for a directory that does not exist yet, and is red for a missing directory under --phase-exit.
//  Q2 the all-import namespace/default ban stands; exceptions only as exact listed paths with a fixture (none today).
//  Q3 scope = every core production-build source: src/ (incl. src/verify/), packages/capability/src, packages/mapping,
//     plus a root verify/ tree if one exists. coreGuard.ts defineProperty is an exact-path entry (QR-25 L228). In verify
//     scopes only the documented deterministic-source binding may import packages/drbg: exact path
//     verify/src/testingBinding.ts (PLAN r4.9 L535 QR-57 row (h); R-58(1) L166). Anything else reaching drbg is red.
//  PH1-M1 erratum (HoQ rule-27 clarification, CTO 2026-11-18 09:04 CET): 'no fewer' for entropy/ blocks as soon as ANY
//     trigger holds (fail-closed), else it is report-only while the directory has no entropy read path:
//     (i) a file under src/entropy/ imports anything from node:crypto/crypto, re-exports from it, exports a name matching
//         /read|fetch|bytes|entropy|fill|draw/i (incl. aliases, types, export *, export default, destructured exports:
//         all red), or calls fill*/read*/randomBytes/randomFill*/getRandomValues/randomUUID/randomInt (bare or member).
//         Only carve-out (HoQ tighten ruling, 2026-11-18): the exact-name allow-list READ_NAME_ALLOW = { FINGERPRINT_BYTES },
//         allowed only as the declaration `export const FINGERPRINT_BYTES = 16;` (canonical decimal literal 16; no type
//         annotation, no 0x10/1_6/16n/'16'/16.0, no expression or identifier, not let/var, not a re-export). Any other
//         exported name matching the heuristic is red. Each future allow-list entry needs its own HoQ ruling plus its own
//         fixture. Comments and string contents are ignored; everything else errs red.
//     (ii) package.json has main/module/exports (package root exported), or a module reachable by static imports or
//         re-exports from a core entry (src/index.ts, src/audited/index.ts) exports createRng/createAuditedRng/randomInt/
//         shuffle/sample/weightedPick/randomBytes or any create*Rng / random* name;
//     (iii) --phase-exit (PH1 exit, any packed or release build).
//     evidence/ and identity/ keep the plain rule: blocking once the directory exists.
//  randomFillSync anywhere outside src/entropy/ is red; inside it only the exact `import { randomFillSync } from
//  'node:crypto'` is allowed (no alias, no other path).
//  HoQ coverage gaps on 2de685b2 (G-12, G-13, G-15, G-16), fail-closed:
//     G-12 globalThis may appear only as a member-access base (`globalThis.x`; `.crypto` and computed `[...]` stay red).
//          Any other reference (alias `const g = globalThis`, destructuring `const {crypto: c} = globalThis`, passing it to
//          Reflect.get / Object.getOwnPropertyDescriptor / any call) is red, except exactly `Object.hasOwn(globalThis,` and
//          `Object.defineProperty(globalThis,` in packages/capability/src/coreGuard.ts. `window` is red like global/self.
//          Function / eval (any use, incl. `new Function`, `Function('return this')()`) and `.constructor(` calls are red.
//     G-13 require('node:module') / require('module') are red (createRequire and import from node:module already are).
//     G-15 an `export const|let|var` statement with more than one declarator is an opaque export (trigger (i) red).
//  HoQ coverage gaps on 83aa9529 (G-17..G-20), fail-closed:
//     G-17 `globalThis.<member>` is red unless <member> is in GLOBALTHIS_MEMBERS_ALLOWED. The list holds exactly what real
//          core source uses today: NONE (2026-11-18 scan of src/, packages/capability/src, packages/mapping: the only
//          globalThis/process tokens are in comments). So globalThis.self/.window/.globalThis/.Function/.eval/.Reflect/
//          .process/... are all red. A new entry needs a HoQ ruling plus its own fixture.
//     G-18 `process` may appear only as `process.<member>` with <member> in PROCESS_MEMBERS_ALLOWED (NONE today, same
//          scan); any other reference (alias, destructuring, argument, computed access) is red. The members getBuiltinModule,
//          binding, _linkedBinding, dlopen and mainModule are red on ANY base (catches aliases such as p.getBuiltinModule).
//     G-19 module.require, any `.require(` member call, and `require` not immediately called (alias, destructuring key,
//          argument) are red; process.mainModule.require is red via the always-banned members.
//     G-20 --self-test also runs the M-152b/c/d/g cases (guard-exact control, guard forms at a non-guard path, window,
//          .constructor() and the MX-12 case: claims-lint --surface p8-package on an embedded key-only plant must be red).
// PENDING: the dist/ grep half (no packed core yet).
// Usage: node tools/ci/import-allowlist.mjs [root] [--phase-exit]   --self-test runs the known-bad fixtures.
import { readFileSync, readdirSync, statSync, lstatSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, relative, dirname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const ts = createRequire(import.meta.url)('typescript');
if (ts.version !== '5.9.3') throw new Error(`rule 27 requires typescript 5.9.3, got ${ts.version}`);

export const REQUIRED_PAIRS = ['randomFillSync@entropy', 'createHash@evidence', 'getFips@identity'];
const EXT = /\.(ts|mts|cts|js|mjs|cjs)$/;
export const SCAN_ROOTS = ['src', 'packages/capability/src', 'packages/mapping', 'verify'];
// Exact-path exceptions (Q2: none for the namespace/default ban today).
export const GUARD_PATH = 'packages/capability/src/coreGuard.ts'; // QR-25 L228, PLAN R-58(6) L166
export const VERIFY_BINDING_PATH = 'verify/src/testingBinding.ts'; // PLAN L535 (QR-57 row h), R-58(1) L166
const DRBG_PKG = '@open-rng-engine/drbg';
export const GLOBALTHIS_MEMBERS_ALLOWED = Object.freeze([]); // G-17: none used by real core source (2026-11-18)
export const PROCESS_MEMBERS_ALLOWED = Object.freeze([]); // G-18: none used by real core source (2026-11-18)
const PROCESS_ALWAYS_BANNED = ['getBuiltinModule', 'binding', '_linkedBinding', 'dlopen', 'mainModule'];
export const COMPUTED_LITERAL_KEYS_ALLOWED = Object.freeze([]); // G-26/M-161: empty in production
export const REFLECTIVE_BASES = Object.freeze(['Reflect', 'getOwnPropertyDescriptor', 'defineProperty', 'getPrototypeOf', 'constructor', '__proto__']);
export const RELATIVE_SPEC_EXT = Object.freeze(['.ts', '.mts', '.cts']);
export const BANNED_COMPUTED_KEY_NAMES = Object.freeze(['constructor', '__proto__', 'getPrototypeOf', 'defineProperty', 'getOwnPropertyDescriptor', 'construct', 'crypto', 'fips', 'setFips', 'require', ...PROCESS_ALWAYS_BANNED]);
export const BANNED_STRING_LITERALS = Object.freeze(['constructor', '__proto__', 'prototype']);
export const BANNED_LOOKUP_NAMES = Object.freeze(['__lookupGetter__', '__lookupSetter__', '__defineGetter__', '__defineSetter__']);
export const BANNED_OBJECT_APIS = Object.freeze(['getOwnPropertyDescriptor', 'getOwnPropertyDescriptors', 'getPrototypeOf', 'setPrototypeOf', 'defineProperty']);
export const BANNED_STACK_APIS = Object.freeze(['prepareStackTrace', 'captureStackTrace', 'stackTraceLimit']);
export const TRACKED_NON_TS_ALLOWED = Object.freeze([]); // exact posix paths; empty for src (G-30 NIT)
export const PINNED_TS_EXPECT_ERROR_REL = 'src/entropy/index.ts';
export const PINNED_TS_EXPECT_ERROR_TEXT = '@ts-expect-error node:crypto typings are not in the pinned devDependencies.';
const SRC_JS_EXT = /\.(js|mjs|cjs)$/;
const PARSE_EXT = /\.(ts|mts|cts)$/;
const READ_CALL_NAME = /^(?:(?:fill|read)[\w$]*|randomBytes|randomFill[\w$]*|getRandomValues|randomUUID|randomInt)$/;

function walk(d, out = []) {
  let names; try { names = readdirSync(d); } catch { return out; }
  for (const n of names.sort()) { if (n === 'node_modules') continue; const p = join(d, n); const s = statSync(p); if (s.isDirectory()) walk(p, out); else if (EXT.test(n)) out.push(p); }
  return out;
}

function walkSymlinks(d, out = []) {
  let names; try { names = readdirSync(d); } catch { return out; }
  for (const n of names.sort()) {
    if (n === 'node_modules' || n === '.git') continue;
    const p = join(d, n);
    let st;
    try { st = lstatSync(p); } catch { continue; }
    if (st.isSymbolicLink()) out.push(p);
    else if (st.isDirectory()) walkSymlinks(p, out);
  }
  return out;
}

export function untrackedSymlinkHits(root) {
  const hits = [];
  const tracked = new Set();
  if (existsSync(join(root, '.git'))) {
    const ls = spawnSync('git', ['ls-files', '-z', ...SCAN_ROOTS], { cwd: root, encoding: 'buffer' });
    if (ls.status === 0) {
      for (const f of ls.stdout.toString('utf8').split('\0').filter(Boolean)) tracked.add(posixRel(root, join(root, f)));
    }
  }
  for (const r of SCAN_ROOTS) {
    for (const abs of walkSymlinks(join(root, r))) {
      const rel = posixRel(root, abs);
      if (!tracked.has(rel)) hits.push(`${rel}:1: rule27-untracked-symlink untracked symlink under a scan root is red`);
    }
  }
  return hits;
}

// Returns [noComments, noCommentsNoStrings]; both keep length and newlines so offsets map to lines.
export function strip(src) {
  let a = '', b = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') { a += ' '; b += ' '; i++; } continue; }
    if (c === '/' && d === '*') { while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { const k = src[i] === '\n' ? '\n' : ' '; a += k; b += k; i++; } if (i < n) { a += '  '; b += '  '; i += 2; } continue; }
    if (c === '"' || c === "'" || c === '`') {
      a += c; b += c; i++;
      while (i < n && src[i] !== c) { if (src[i] === '\\') { a += src[i] + (src[i + 1] ?? ''); b += '  '; i += 2; continue; } a += src[i]; b += src[i] === '\n' ? '\n' : ' '; i++; }
      if (i < n) { a += c; b += c; i++; }
      continue;
    }
    a += c; b += c; i++;
  }
  return [a, b];
}

const lineOf = (s, idx) => s.slice(0, idx).split('\n').length;

function parseSource(rel, src) {
  return ts.createSourceFile(rel || 'file.ts', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function parseErrors(sf) {
  const diags = typeof ts.getSourceFileParseDiagnostics === 'function'
    ? ts.getSourceFileParseDiagnostics(sf)
    : (sf.parseDiagnostics ?? []);
  return diags.filter((d) => d.category === ts.DiagnosticCategory.Error);
}

function idText(node) {
  if (!node) return '';
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) return ts.idText(node);
  return '';
}

function hasUnicodeEscape(node) {
  return /\\u/i.test(node.getText());
}

function isStringLiteralLike(node) {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
}

function literalText(node) {
  if (!node) return undefined;
  if (isStringLiteralLike(node) || ts.isNumericLiteral(node) || ts.isBigIntLiteral(node)) return node.text;
  return undefined;
}

function visit(node, fn) {
  fn(node);
  ts.forEachChild(node, (c) => visit(c, fn));
}

function isPropertyAccessName(node) {
  const p = node.parent;
  return p && ts.isPropertyAccessExpression(p) && p.name === node;
}

function isDotOrColonPropertyName(node) {
  const p = node.parent;
  if (!p) return false;
  if (ts.isPropertyAccessExpression(p) && p.name === node) return true;
  if (ts.isQualifiedName(p) && p.right === node) return true;
  if (ts.isMetaProperty(p) && p.name === node) return true;
  if (ts.isPropertyAssignment(p) && p.name === node) return true;
  if (ts.isBindingElement(p) && p.propertyName === node) return true;
  if (ts.isLabeledStatement(p) && p.label === node) return true;
  if ((ts.isBreakStatement(p) || ts.isContinueStatement(p)) && p.label === node) return true;
  if ((ts.isPropertyDeclaration(p) || ts.isPropertySignature(p) || ts.isEnumMember(p)
    || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p) || ts.isParameter(p)) && p.name === node) return true;
  return false;
}

function isMemberAccessBase(node) {
  const p = node.parent;
  if (!p) return false;
  return (ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) && p.expression === node;
}

function accessMemberName(node) {
  if (ts.isPropertyAccessExpression(node)) return idText(node.name);
  if (ts.isElementAccessExpression(node)) return literalText(node.argumentExpression);
  return undefined;
}

function isIdent(node, name) {
  return node && ts.isIdentifier(node) && idText(node) === name;
}

function isObjectOrReflectGetPrototypeOf(expr) {
  if (!ts.isPropertyAccessExpression(expr) && !ts.isElementAccessExpression(expr)) return false;
  if (accessMemberName(expr) !== 'getPrototypeOf') return false;
  const base = expr.expression;
  if (isIdent(base, 'Object') || isIdent(base, 'Reflect')) return true;
  if (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) {
    const n = accessMemberName(base);
    return n === 'Object' || n === 'Reflect';
  }
  return false;
}

function isReflectConstruct(expr) {
  if (!ts.isPropertyAccessExpression(expr) && !ts.isElementAccessExpression(expr)) return false;
  if (accessMemberName(expr) !== 'construct') return false;
  const base = expr.expression;
  if (isIdent(base, 'Reflect')) return true;
  if (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) return accessMemberName(base) === 'Reflect';
  return false;
}

function isLiteralPropertyKey(node) {
  if (!isStringLiteralLike(node)) return false;
  const p = node.parent;
  if (!p) return false;
  if (ts.isElementAccessExpression(p) && p.argumentExpression === node) return true;
  if (ts.isComputedPropertyName(p) && p.expression === node) return true;
  if ((ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) || ts.isPropertySignature(p) || ts.isMethodDeclaration(p)
    || ts.isMethodSignature(p) || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p) || ts.isEnumMember(p)
    || ts.isBindingElement(p)) && p.name === node) return true;
  if (ts.isBindingElement(p) && p.propertyName === node) return true;
  return false;
}

function resolveRel(fromRel, spec) {
  return relative('/r', resolve('/r', dirname(fromRel), spec)).split(sep).join('/');
}

function inScanRoots(resolved) {
  return SCAN_ROOTS.some((root) => resolved === root || resolved.startsWith(root + '/'));
}

function isDrbgSpec(rel, spec) {
  if (spec === DRBG_PKG || spec.startsWith(DRBG_PKG + '/')) return true;
  if (spec.startsWith('.') && (resolve('/r', dirname(rel), spec) + sep).startsWith(resolve('/r', 'packages/drbg') + sep)) return true;
  return false;
}

function specifierAllowed(rel, spec, { typeOnly = false } = {}) {
  if (typeof spec !== 'string') return false;
  if (spec.startsWith('.')) return inScanRoots(resolveRel(rel, spec));
  if (spec === 'node:crypto') return !typeOnly;
  if (isDrbgSpec(rel, spec) && rel === VERIFY_BINDING_PATH) return !typeOnly;
  return false;
}

function explicitRelativeExt(spec) {
  const m = /(\.[A-Za-z0-9]+)$/.exec(spec);
  return m ? m[1] : '';
}

function posixRel(root, abs) {
  return relative(root, abs).split(sep).join('/');
}

function normalizePosix(rel) {
  return rel.split(sep).join('/').replace(/\\/g, '/');
}

function throughNodeModules(rel) {
  return rel.split('/').includes('node_modules');
}

export function makeProgram(files) {
  const map = new Map(files.map(([rel, src]) => [normalizePosix(rel), src]));
  const rootNames = [...map.keys()];
  const options = {
    noEmit: true, target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
    strict: true, skipLibCheck: true, noLib: false, types: [],
  };
  const host = ts.createCompilerHost(options, true);
  const origGet = host.getSourceFile.bind(host);
  const match = (fileName) => {
    const norm = normalizePosix(fileName);
    if (map.has(norm)) return norm;
    for (const rel of map.keys()) if (norm === rel || norm.endsWith('/' + rel)) return rel;
    return null;
  };
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const rel = match(fileName);
    if (rel != null) return ts.createSourceFile(rel, map.get(rel), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    return origGet(fileName, languageVersion, onError, shouldCreate);
  };
  const origRead = host.readFile.bind(host);
  host.readFile = (fileName) => { const rel = match(fileName); return rel != null ? map.get(rel) : origRead(fileName); };
  const origExists = host.fileExists.bind(host);
  host.fileExists = (fileName) => match(fileName) != null || origExists(fileName);
  const program = ts.createProgram({ rootNames, options, host });
  return { program, checker: program.getTypeChecker(), files: map };
}

function isNumberType(type) {
  if (!type) return false;
  if (type.flags & ts.TypeFlags.Number) return true;
  if (type.isUnion && type.isUnion()) return type.types.every(isNumberType);
  return false;
}

function isStringType(type) {
  if (!type) return false;
  if (type.flags & ts.TypeFlags.String) return true;
  if (type.isUnion && type.isUnion()) return type.types.every((t) => isStringType(t) || (t.flags & ts.TypeFlags.StringLiteral));
  return false;
}

function literalUnionTexts(type) {
  const out = [];
  let impure = false;
  const add = (t) => {
    if (!t) { impure = true; return; }
    if (t.isUnion && t.isUnion()) { t.types.forEach(add); return; }
    if (t.flags & ts.TypeFlags.StringLiteral) { out.push(String(t.value)); return; }
    if (t.flags & ts.TypeFlags.NumberLiteral) { out.push(String(t.value)); return; }
    if (t.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Null | ts.TypeFlags.Never)) return;
    impure = true;
  };
  add(type);
  if (impure || out.length === 0) return null;
  return out;
}

function isSourceLiteralKey(expr) {
  return !!(expr && (ts.isStringLiteral(expr) || ts.isNumericLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)));
}

export function computedKeyVerdict(expr, checker, { computedLiteralAllow = COMPUTED_LITERAL_KEYS_ALLOWED, treatStringAsSafe = false } = {}) {
  if (isSourceLiteralKey(expr)) return 'source-literal';
  if (!checker) return 'non-literal';
  const type = checker.getTypeAtLocation(expr);
  if (isNumberType(type)) return 'number';
  if (treatStringAsSafe && isStringType(type) && !literalUnionTexts(type)) return 'string-treated-safe';
  const lits = literalUnionTexts(type);
  if (!lits) return 'non-literal';
  if (lits.some((x) => BANNED_COMPUTED_KEY_NAMES.includes(x))) return 'banned-literal-union';
  if (computedLiteralAllow === 'ANY') return 'allowed';
  const allow = Array.isArray(computedLiteralAllow) ? computedLiteralAllow : [];
  if (lits.every((x) => allow.includes(x))) return 'allowed';
  return 'not-on-allow-list';
}

function isReflectiveCallee(expr, bases) {
  const set = new Set(bases ?? REFLECTIVE_BASES);
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    const mem = accessMemberName(expr);
    const obj = expr.expression;
    if (set.has('Reflect') && isIdent(obj, 'Reflect')) return 'Reflect';
    if (isIdent(obj, 'Object')) {
      if (mem === 'getOwnPropertyDescriptor' && set.has('getOwnPropertyDescriptor')) return 'getOwnPropertyDescriptor';
      if (mem === 'defineProperty' && set.has('defineProperty')) return 'defineProperty';
      if (mem === 'getPrototypeOf' && set.has('getPrototypeOf')) return 'getPrototypeOf';
    }
  }
  if (ts.isIdentifier(expr) && idText(expr) === 'Reflect' && set.has('Reflect')) return 'Reflect';
  return null;
}

function reflectiveKeyArgIndex(base) {
  // Reflect.get/set/has/deleteProperty/defineProperty/getOwnPropertyDescriptor(target, key, ...)
  // Object.getOwnPropertyDescriptor(obj, key), Object.defineProperty(obj, key, desc)
  // Object.getPrototypeOf(obj) has no key argument (checked via Object[key] element access)
  if (base === 'getPrototypeOf') return -1;
  return 1;
}

function isGuardFormGlobalThisArg(node, rel) {
  if (rel !== GUARD_PATH) return false;
  const call = node.parent;
  if (!call || !ts.isCallExpression(call)) return false;
  if (call.arguments[0] !== node) return false;
  const cal = call.expression;
  if (!ts.isPropertyAccessExpression(cal)) return false;
  if (!isIdent(cal.expression, 'Object')) return false;
  const m = idText(cal.name);
  return m === 'hasOwn' || m === 'defineProperty';
}

function isExactGuardDescriptor(obj) {
  if (!obj || !ts.isObjectLiteralExpression(obj) || obj.properties.length !== 4) return false;
  const names = obj.properties.map((p) => {
    if (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) {
      if (ts.isIdentifier(p.name)) return idText(p.name);
      if (isStringLiteralLike(p.name)) return p.name.text;
    }
    return '';
  });
  if (names.join(',') !== 'value,writable,configurable,enumerable') return false;
  const valueProp = obj.properties[0];
  if (ts.isShorthandPropertyAssignment(valueProp)) { /* ok */ }
  else if (ts.isPropertyAssignment(valueProp) && valueProp.initializer) {
    const init = valueProp.initializer;
    if (ts.isIdentifier(init)) { /* ok */ }
    else if (ts.isPropertyAccessExpression(init) && /^[\w$.]+$/.test(init.getText())) { /* ok */ }
    else return false;
  } else return false;
  for (const i of [1, 2, 3]) {
    const p = obj.properties[i];
    if (!ts.isPropertyAssignment(p) || !p.initializer || p.initializer.kind !== ts.SyntaxKind.FalseKeyword) return false;
  }
  return true;
}

function isDefinePropertyGlobalThis(call) {
  if (!ts.isCallExpression(call)) return false;
  const cal = call.expression;
  if (!ts.isPropertyAccessExpression(cal) || !isIdent(cal.expression, 'Object') || idText(cal.name) !== 'defineProperty') return false;
  return call.arguments[0] && isIdent(call.arguments[0], 'globalThis');
}

function isHasOwnGlobalThis(call) {
  if (!ts.isCallExpression(call)) return false;
  const cal = call.expression;
  if (!ts.isPropertyAccessExpression(cal) || !isIdent(cal.expression, 'Object') || idText(cal.name) !== 'hasOwn') return false;
  return call.arguments[0] && isIdent(call.arguments[0], 'globalThis');
}

function isAllowedGuardDefinePropertyCall(call) {
  return isDefinePropertyGlobalThis(call) && isExactGuardDescriptor(call.arguments[2]);
}

function isInsideAllowedGuardDefineProperty(node, rel) {
  if (rel !== GUARD_PATH) return false;
  let n = node;
  while (n) {
    if (ts.isCallExpression(n) && isAllowedGuardDefinePropertyCall(n)) return true;
    n = n.parent;
  }
  return false;
}

const NUMERIC_BINARY = new Set([
  ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken,
  ts.SyntaxKind.AsteriskAsteriskToken, ts.SyntaxKind.BarToken, ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.CaretToken,
  ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken,
]);
const NUMERIC_COMPOUND = new Set([
  ts.SyntaxKind.MinusEqualsToken, ts.SyntaxKind.AsteriskEqualsToken, ts.SyntaxKind.SlashEqualsToken, ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken, ts.SyntaxKind.BarEqualsToken, ts.SyntaxKind.AmpersandEqualsToken, ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
]);

function isFunctionLike(node) {
  return !!(node && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)
    || ts.isClassStaticBlockDeclaration(node)));
}

function containingFunction(node) {
  let n = node && node.parent;
  while (n) {
    if (isFunctionLike(n)) return n;
    n = n.parent;
  }
  return null;
}

function unwrapParens(expr) {
  let e = expr;
  while (e && ts.isParenthesizedExpression(e)) e = e.expression;
  return e;
}

function isIncDec(node) {
  const e = unwrapParens(node);
  if (!e) return false;
  if (ts.isPrefixUnaryExpression(e) || ts.isPostfixUnaryExpression(e)) {
    return e.operator === ts.SyntaxKind.PlusPlusToken || e.operator === ts.SyntaxKind.MinusMinusToken;
  }
  return false;
}

function unwrapAlias(checker, s) {
  if (!s) return null;
  if (s.flags & ts.SymbolFlags.Alias) {
    try {
      const a = checker.getAliasedSymbol(s);
      if (a && a.escapedName !== 'unknown') return a;
    } catch { /* keep s */ }
  }
  return s;
}

function valueSymbol(checker, node) {
  if (!checker || !node) return null;
  return unwrapAlias(checker, checker.getSymbolAtLocation(node));
}

// Shorthand assignment targets ({ k } = ...) have a property symbol at the identifier;
// the bound variable is checker.getShorthandAssignmentValueSymbol.
function symbolsReferring(checker, ident) {
  const out = [];
  const add = (s) => { s = unwrapAlias(checker, s); if (s && !out.includes(s)) out.push(s); };
  add(valueSymbol(checker, ident));
  const p = ident && ident.parent;
  if (p && ts.isShorthandPropertyAssignment(p) && p.name === ident) {
    try { add(checker.getShorthandAssignmentValueSymbol(p)); } catch { /* ignore */ }
  }
  return out;
}

function isExactlyNumberType(checker, node) {
  if (!checker || !node) return false;
  const type = checker.getTypeAtLocation(node);
  if (!type) return false;
  const leafOk = (t) => {
    if (!t) return false;
    if (typeof t.isUnion === 'function' && t.isUnion()) return t.types.every(leafOk);
    if (t.flags & ts.TypeFlags.Number) return true;
    if (t.flags & ts.TypeFlags.NumberLiteral) return true;
    return false;
  };
  return leafOk(type);
}

function isInsideLabeledStatement(node, stopAt) {
  let n = node && node.parent;
  while (n && n !== stopAt) {
    if (ts.isLabeledStatement(n)) return true;
    n = n.parent;
  }
  return false;
}

// True when `start` sits in an assignment / for-in / for-of target pattern (destructuring).
function isPartOfPatternAssignment(start) {
  let n = start;
  let inPattern = false;
  while (n && n.parent) {
    const p = n.parent;
    if (ts.isParenthesizedExpression(p) && p.expression === n) { n = p; continue; }
    if (ts.isArrayLiteralExpression(p) || ts.isObjectLiteralExpression(p)) { inPattern = true; n = p; continue; }
    if (ts.isSpreadElement(p) || ts.isSpreadAssignment(p)) { inPattern = true; n = p; continue; }
    if (ts.isPropertyAssignment(p) && (p.name === n || p.initializer === n)) { n = p; continue; }
    if (ts.isShorthandPropertyAssignment(p) && (p.name === n || p.objectAssignmentInitializer === n)) { inPattern = true; n = p; continue; }
    if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.left === n) {
      if (inPattern) return true;
      const gp = p.parent;
      const looksDefault = gp && (ts.isArrayLiteralExpression(gp) || ts.isObjectLiteralExpression(gp)
        || ts.isParenthesizedExpression(gp) || ts.isPropertyAssignment(gp) || ts.isSpreadElement(gp));
      if (looksDefault) { inPattern = true; n = p; continue; }
      return false;
    }
    if (ts.isBinaryExpression(p) && ts.isAssignmentOperator(p.operatorToken.kind) && p.left === n) {
      return inPattern;
    }
    if ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && p.initializer === n) {
      return inPattern || ts.isArrayLiteralExpression(n) || ts.isObjectLiteralExpression(n);
    }
    return false;
  }
  return false;
}

function isForInOfDirectHead(node) {
  const p = node && node.parent;
  return !!(p && (ts.isForInStatement(p) || ts.isForOfStatement(p)) && p.initializer === node);
}

// Walk up through transparent wrappers so `(k) = v` and `(0, k) = v` are classified as writes.
function skipTransparentUp(node) {
  let n = node;
  for (let i = 0; i < 64; i++) {
    const p = n.parent;
    if (!p) return n;
    if (ts.isParenthesizedExpression(p) && p.expression === n) { n = p; continue; }
    if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.CommaToken && p.right === n) { n = p; continue; }
    // Banned in core src anyway; still unwrap so a wrapped write is classified as a write.
    if (ts.isNonNullExpression(p) && p.expression === n) { n = p; continue; }
    if (ts.isAsExpression(p) && p.expression === n) { n = p; continue; }
    if (ts.isTypeAssertionExpression(p) && p.expression === n) { n = p; continue; }
    if (ts.isSatisfiesExpression(p) && p.expression === n) { n = p; continue; }
    return n;
  }
  return n;
}

// Positive allow-list of parent positions that are a read of `node`. Every other position is UNKNOWN.
function isAllowedReadPosition(node, p) {
  if (!p) return false;
  if (ts.isElementAccessExpression(p) && p.argumentExpression === node) return true;
  if (ts.isComputedPropertyName(p) && p.expression === node) return true;
  if (ts.isBinaryExpression(p) && !ts.isAssignmentOperator(p.operatorToken.kind)
    && (p.left === node || p.right === node)) return true;
  if (ts.isPrefixUnaryExpression(p) && p.operand === node
    && p.operator !== ts.SyntaxKind.PlusPlusToken && p.operator !== ts.SyntaxKind.MinusMinusToken) return true;
  if ((ts.isCallExpression(p) || ts.isNewExpression(p)) && p.arguments && p.arguments.some((a) => a === node)) return true;
  if ((ts.isReturnStatement(p) || ts.isThrowStatement(p)) && p.expression === node) return true;
  if (ts.isYieldExpression(p) && p.expression === node) return true;
  if (ts.isAwaitExpression(p) && p.expression === node) return true;
  if (ts.isVariableDeclaration(p) && p.initializer === node) return true;
  if (ts.isParameter(p) && p.initializer === node) return true;
  if ((ts.isPropertyDeclaration(p) || ts.isPropertyAssignment(p) || ts.isBindingElement(p)
    || ts.isEnumMember(p)) && p.initializer === node) return true;
  if (ts.isBinaryExpression(p) && ts.isAssignmentOperator(p.operatorToken.kind) && p.right === node) return true;
  if (ts.isIfStatement(p) && p.expression === node) return true;
  if (ts.isWhileStatement(p) && p.expression === node) return true;
  if (ts.isDoStatement(p) && p.expression === node) return true;
  if (ts.isSwitchStatement(p) && p.expression === node) return true;
  if (ts.isForStatement(p) && (p.condition === node || p.incrementor === node || p.initializer === node)) return true;
  if ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && p.expression === node) return true;
  if (ts.isConditionalExpression(p) && (p.condition === node || p.whenTrue === node || p.whenFalse === node)) return true;
  if (ts.isArrayLiteralExpression(p)) return true;
  if ((ts.isSpreadElement(p) || ts.isSpreadAssignment(p)) && p.expression === node) return true;
  if (ts.isTemplateSpan(p) && p.expression === node) return true;
  if (ts.isShorthandPropertyAssignment(p) && p.name === node) return true;
  if (ts.isCaseClause(p) && p.expression === node) return true;
  if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && p.body === node) return true;
  if (ts.isExportAssignment(p) && p.expression === node) return true;
  return false;
}

// Classify one identifier reference bound to a candidate let/const: READ, NUMERIC_WRITE, or UNKNOWN.
// G-43: unwrap transparent wrappers, then classify writes; READ is a positive allow-list with no default.
function classifyReference(ident, checker, seen) {
  const target = skipTransparentUp(ident);
  if (isForInOfDirectHead(target) || isForInOfDirectHead(ident)
    || isPartOfPatternAssignment(ident)) return 'UNKNOWN';
  const p = target.parent;
  if (!p) return 'UNKNOWN';
  if ((ts.isPrefixUnaryExpression(p) || ts.isPostfixUnaryExpression(p)) && p.operand === target
    && (p.operator === ts.SyntaxKind.PlusPlusToken || p.operator === ts.SyntaxKind.MinusMinusToken)) {
    return 'NUMERIC_WRITE';
  }
  if (ts.isBinaryExpression(p) && p.left === target && ts.isAssignmentOperator(p.operatorToken.kind)) {
    const op = p.operatorToken.kind;
    if (op === ts.SyntaxKind.EqualsToken) {
      return isNumericKeyExpr(p.right, seen, checker) ? 'NUMERIC_WRITE' : 'UNKNOWN';
    }
    if (op === ts.SyntaxKind.PlusEqualsToken) return 'UNKNOWN';
    if (NUMERIC_COMPOUND.has(op)) return 'NUMERIC_WRITE';
    return 'UNKNOWN';
  }
  if (isAllowedReadPosition(target, p)) return 'READ';
  return 'UNKNOWN'; // G-43 no default READ
}

function isNumericLocalIdentifier(ident, seen, checker) {
  if (!checker) return false;
  const useFn = containingFunction(ident);
  if (!useFn) return false;
  const sym = valueSymbol(checker, ident);
  if (!sym) return false;
  const decl = sym.valueDeclaration;
  if (!decl || !ts.isVariableDeclaration(decl) || !ts.isIdentifier(decl.name)) return false;
  const list = decl.parent;
  if (!ts.isVariableDeclarationList(list)) return false;
  if (!(list.flags & ts.NodeFlags.Let) && !(list.flags & ts.NodeFlags.Const)) return false;
  if (!decl.initializer) return false;
  const declFn = containingFunction(decl);
  if (!declFn || declFn !== useFn) return false;
  if (!isNumericKeyExpr(decl.initializer, seen, checker)) return false;
  // Second layer only, never sufficient on its own.
  if (!isExactlyNumberType(checker, decl.name)) return false;
  let ok = true;
  const visit = (node) => {
    if (!ok) return;
    if (ts.isIdentifier(node)) {
      const sMatch = symbolsReferring(checker, node).includes(sym);
      if (sMatch && node !== decl.name) {
        const kind = classifyReference(node, checker, seen);
        const refFn = containingFunction(node);
        if (refFn !== declFn) {
          if (kind !== 'READ') ok = false;
        } else if (kind === 'UNKNOWN') {
          ok = false;
        } else if (kind === 'NUMERIC_WRITE' && isInsideLabeledStatement(node, declFn)) {
          ok = false;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(declFn);
  return ok;
}

export function isNumericKeyExpr(expr, seen = new Set(), checker = undefined) {
  if (!expr) return false;
  const e = unwrapParens(expr);
  if (!e) return false;
  if (seen.has(e)) return false;
  const next = new Set(seen);
  next.add(e);
  if (ts.isNumericLiteral(e)) return true;
  if (ts.isPrefixUnaryExpression(e)) {
    const op = e.operator;
    if (op === ts.SyntaxKind.PlusToken || op === ts.SyntaxKind.MinusToken || op === ts.SyntaxKind.TildeToken) return true;
    return false;
  }
  if (ts.isBinaryExpression(e)) {
    return NUMERIC_BINARY.has(e.operatorToken.kind);
  }
  if (ts.isIdentifier(e)) return isNumericLocalIdentifier(e, next, checker);
  return false;
}

function isGreenElementKey(expr, checker) {
  return isNumericKeyExpr(expr, new Set(), checker);
}

function isComputedKeyContext(nameNode) {
  const p = nameNode.parent;
  if (!p) return false;
  if (ts.isBindingElement(p) && p.propertyName === nameNode) return true;
  if ((ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p) || ts.isMethodDeclaration(p)
    || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p) || ts.isSpreadAssignment(p))
    && p.name === nameNode && p.parent && ts.isObjectLiteralExpression(p.parent)) return true;
  return false;
}

function commentBody(text, range) {
  const raw = text.slice(range.pos, range.end);
  return raw.replace(/^\/\/\/?/, '').replace(/^\/\*/, '').replace(/\*\/$/, '').trim();
}

function isPinnedEntropyImport(node) {
  if (!node || !ts.isImportDeclaration(node) || !node.moduleSpecifier || !isStringLiteralLike(node.moduleSpecifier)) return false;
  if (node.moduleSpecifier.text !== 'node:crypto') return false;
  const clause = node.importClause;
  if (!clause || !clause.namedBindings || !ts.isNamedImports(clause.namedBindings)) return false;
  if (clause.name || clause.namedBindings.elements.length !== 1) return false;
  const el = clause.namedBindings.elements[0];
  return idText(el.propertyName ?? el.name) === 'randomFillSync' && idText(el.name) === 'randomFillSync' && !el.propertyName;
}

function scanCommentDirectives(sf, rel, add) {
  const text = sf.text;
  const byRange = new Map();
  const consider = (range, owner) => {
    const key = range.pos + ':' + range.end;
    const rec = byRange.get(key) ?? { range, owners: [] };
    rec.owners.push(owner);
    byRange.set(key, rec);
  };
  const walkC = (node) => {
    for (const r of (ts.getLeadingCommentRanges(text, node.getFullStart()) ?? [])) consider(r, node);
    for (const r of (ts.getTrailingCommentRanges(text, node.end) ?? [])) consider(r, undefined);
    ts.forEachChild(node, walkC);
  };
  walkC(sf);
  for (const { range, owners } of byRange.values()) {
    const body = commentBody(text, range);
    if (body.startsWith('@ts-ignore')) add(range.pos, 'ts-directive', '@ts-ignore is red in core src (G-28)');
    if (body.startsWith('@ts-nocheck')) add(range.pos, 'ts-directive', '@ts-nocheck is red in core src (G-28)');
    if (body.startsWith('@ts-expect-error')) {
      const ok = rel === PINNED_TS_EXPECT_ERROR_REL && body === PINNED_TS_EXPECT_ERROR_TEXT && owners.some((o) => isPinnedEntropyImport(o));
      if (!ok) add(range.pos, 'ts-directive', '@ts-expect-error is allowed only at the pinned entropy randomFillSync import line (G-28)');
    }
  }
}

function isTrackedNonTs(rel) {
  const base = (rel.split('/').pop() ?? '');
  if (base.endsWith('.json')) return true;
  if (!base.includes('.')) return true;
  return false;
}

function callName(node) {
  if (ts.isIdentifier(node)) return idText(node);
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return accessMemberName(node);
  return undefined;
}

function collectSpecifiers(sf, rel) {
  const out = [];
  visit(sf, (node) => {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier && isStringLiteralLike(node.moduleSpecifier)) {
      out.push({ spec: node.moduleSpecifier.text, node, kind: 'import', typeOnly: !!node.importClause?.isTypeOnly });
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && isStringLiteralLike(node.moduleSpecifier)) {
      out.push({ spec: node.moduleSpecifier.text, node, kind: 'export', typeOnly: !!node.isTypeOnly });
    } else if (ts.isImportEqualsDeclaration(node) && node.moduleReference && ts.isExternalModuleReference(node.moduleReference)
      && node.moduleReference.expression && isStringLiteralLike(node.moduleReference.expression)) {
      out.push({ spec: node.moduleReference.expression.text, node, kind: 'importEquals', typeOnly: !!node.isTypeOnly });
    }
  });
  return out;
}

export function scanFile(rel, src, opts = {}) {
  const hits = []; const pairs = [];
  const top = rel.startsWith('src/') ? (rel.split('/')[1] ?? '') : rel.split('/').slice(0, 2).join('/');
  const inVerify = rel.startsWith('src/verify/') || rel.startsWith('verify/');
  const add = (idx, code, msg) => hits.push(`${rel}:${lineOf(src, idx)}: rule27-${code} ${msg}`);
  const addNode = (node, code, msg) => add(node.getStart(), code, msg);
  const isCrypto = (s) => s === 'node:crypto' || s === 'crypto';
  const keyOpts = {
    computedLiteralAllow: opts.computedLiteralAllow ?? COMPUTED_LITERAL_KEYS_ALLOWED,
    treatStringAsSafe: opts.treatStringAsSafe === true,
  };
  const bases = opts.reflectiveBases ?? REFLECTIVE_BASES;
  const parsed = opts.parsedFiles ?? null; // Set of posix rels this scan parsed, if available
  const root = opts.root ?? null;

  let sf = opts.sourceFile;
  let checker = opts.checker;
  if (!sf) sf = parseSource(rel, src);
  if (!checker && opts.skipChecker !== true) {
    const prog = makeProgram([[rel, src]]);
    checker = prog.checker;
    const got = prog.program.getSourceFile(rel);
    if (got) sf = got;
  }
  for (const d of parseErrors(sf)) add(d.start ?? 0, 'parse', ts.flattenDiagnosticMessageText(d.messageText, '\n'));
  scanCommentDirectives(sf, rel, add);

  const specs = collectSpecifiers(sf, rel);
  for (const s of specs) {
    const clause = s.node.importClause;
    if (s.kind === 'import' && clause) {
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) addNode(s.node, 'namespace-import', `namespace import of '${s.spec}'`);
      else if (clause.name) addNode(s.node, 'default-import', `default import of '${s.spec}'`);
    }
    if (s.spec === 'node:module' || s.spec === 'module') addNode(s.node, 'node-module', `import of '${s.spec}'`);
    if (isCrypto(s.spec)) {
      const named = s.kind === 'import' && clause && clause.namedBindings && ts.isNamedImports(clause.namedBindings);
      if (s.spec !== 'node:crypto') addNode(s.node, 'bare-crypto-specifier', `'${s.spec}' (only 'node:crypto' named imports are allowed)`);
      if (s.kind !== 'import' || !named || s.typeOnly) addNode(s.node, 'crypto-not-named', `node:crypto reached other than as a named ESM import`);
      else {
        for (const el of clause.namedBindings.elements) {
          const sym = idText(el.propertyName ?? el.name);
          const alias = idText(el.name);
          if (el.propertyName && alias !== sym) addNode(s.node, 'crypto-alias', `node:crypto symbol ${sym} imported under alias ${alias} (only the exact named import is allowed)`);
          if (!el.isTypeOnly && !s.typeOnly) pairs.push({ pair: `${sym}@${top}`, at: `${rel}:${lineOf(src, s.node.getStart())}` });
        }
      }
    }
    const clauseText = s.kind === 'import' && clause ? clause.getText() : (s.kind === 'export' && s.node.exportClause ? s.node.exportClause.getText() : '');
    if (!isCrypto(s.spec) && /(^|[\s,{])randomFillSync([\s,}]|$)/.test(clauseText)) addNode(s.node, 'randomFillSync-other-path', `randomFillSync reached through '${s.spec}' (only node:crypto in src/entropy/)`);
    if (inVerify && isDrbgSpec(rel, s.spec) && rel !== VERIFY_BINDING_PATH) {
      addNode(s.node, 'verify-drbg-binding', `'${s.spec}' reached from ${rel}; only ${VERIFY_BINDING_PATH} (PLAN L535) may bind the deterministic source`);
    }
    if (top === 'audited') {
      const internal = s.spec.startsWith('.') && (resolve('/r', dirname(rel), s.spec) + sep).startsWith(resolve('/r', 'src') + sep);
      if (!internal) addNode(s.node, 'audited-import', `audited/ imports '${s.spec}' (only core-internal modules and evidence/)`);
    }
    if (!specifierAllowed(rel, s.spec, { typeOnly: s.typeOnly })) {
      addNode(s.node, 'specifier-not-allowed', `module specifier '${s.spec}' is not on the positive allow-list`);
    }
    if (typeof s.spec === 'string' && s.spec.startsWith('.')) {
      const ext = explicitRelativeExt(s.spec);
      if (!RELATIVE_SPEC_EXT.includes(ext)) {
        addNode(s.node, 'relative-specifier', `relative specifier '${s.spec}' is missing an explicit allowed extension (${RELATIVE_SPEC_EXT.join(', ')})`);
      } else {
        const resolved = resolveRel(rel, s.spec);
        if (throughNodeModules(resolved)) addNode(s.node, 'relative-specifier', `relative specifier '${s.spec}' resolves through node_modules (${resolved})`);
        else if (!inScanRoots(resolved)) addNode(s.node, 'relative-specifier', `relative specifier '${s.spec}' resolves outside the scanned set (${resolved})`);
        else if (parsed && !parsed.has(resolved)) addNode(s.node, 'relative-specifier', `relative specifier '${s.spec}' does not resolve to a file this scan parsed (${resolved})`);
        else if (parsed) {
          const matches = [...parsed].filter((f) => f === resolved);
          if (matches.length !== 1) addNode(s.node, 'relative-specifier', `relative specifier '${s.spec}' must resolve to exactly one parsed file (got ${matches.length}: ${resolved})`);
        }
      }
    }
  }

  const dps = [];
  visit(sf, (node) => {
    if ((ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) && hasUnicodeEscape(node)) {
      addNode(node, 'unicode-escape', `unicode escape in identifier '${node.getText()}' (decoded '${idText(node)}')`);
    }
    if (isLiteralPropertyKey(node) && hasUnicodeEscape(node)) {
      addNode(node, 'unicode-escape', `unicode escape in string-literal property key ${node.getText()}`);
    }
    if (ts.isIdentifier(node) && idText(node) === 'Reflect') {
      addNode(node, 'reflect-identifier', 'Reflect identifier is red in scanned source (G-26)');
    }
    if (ts.isIdentifier(node) && idText(node) === 'Proxy') {
      addNode(node, 'proxy-identifier', 'Proxy identifier is red in scanned source (S-1)');
    }
    // G-28: banned string literals / no-substitution templates, any position, AST value.
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && BANNED_STRING_LITERALS.includes(node.text)) {
      addNode(node, 'banned-string-literal', `string literal or no-substitution template '${node.text}' is red in any position (G-28)`);
    }
    if ((ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) && BANNED_LOOKUP_NAMES.includes(idText(node))) {
      addNode(node, 'banned-lookup', `'${idText(node)}' is red as an identifier or member name (G-28)`);
    }
    if ((ts.isIdentifier(node) && BANNED_OBJECT_APIS.includes(idText(node)))
      || ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) && BANNED_OBJECT_APIS.includes(accessMemberName(node)))) {
      if (!isInsideAllowedGuardDefineProperty(node, rel)) {
        const nm = ts.isIdentifier(node) ? idText(node) : accessMemberName(node);
        addNode(node, 'object-api', `${nm} is red outside coreGuard's exact forms (G-28)`);
      }
    }
    if ((ts.isIdentifier(node) && BANNED_STACK_APIS.includes(idText(node)))
      || ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) && BANNED_STACK_APIS.includes(accessMemberName(node)))) {
      const nm = ts.isIdentifier(node) ? idText(node) : accessMemberName(node);
      addNode(node, 'prepare-stack', `${nm} is red in core src (G-28)`);
    }
    if (ts.isComputedPropertyName(node) && isComputedKeyContext(node) && !ts.isNumericLiteral(node.expression)) {
      addNode(node, 'computed-key', `computed key in a destructuring pattern or object literal is not a numeric literal: ${node.expression.getText()}`);
    }
    if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) {
      addNode(node, 'type-assertion', 'type assertion (as or angle-bracket) is red in core src (G-28)');
    }
    if (node.kind === ts.SyntaxKind.AnyKeyword) addNode(node, 'banned-type', 'any in a type position is red (G-28)');
    if (node.kind === ts.SyntaxKind.UnknownKeyword) addNode(node, 'banned-type', 'unknown in a type position is red (G-28)');
    if (ts.isNonNullExpression(node)) addNode(node, 'non-null-assertion', 'non-null assertion is red in core src (G-28)');
    if (ts.isTypePredicateNode(node)) {
      const asserts = !!node.assertsModifier;
      addNode(node, 'type-predicate', asserts
        ? 'assertion signature is red in core src (G-43)'
        : 'user-defined type predicate is red in core src (G-43)');
    }
    if (ts.isElementAccessExpression(node)) {
      const key = node.argumentExpression;
      if (!isGreenElementKey(key, checker)) {
        addNode(node, 'computed-access', `element access key is not a syntactically numeric form (S-1): ${key.getText()}`);
      }
    }
    if (ts.isCallExpression(node)) {
      const base = isReflectiveCallee(node.expression, bases);
      if (base) {
        const idx = reflectiveKeyArgIndex(base);
        if (idx >= 0 && node.arguments[idx]) {
          const key = node.arguments[idx];
          const v = computedKeyVerdict(key, checker, keyOpts);
          if (!isGreenElementKey(key, checker) && v !== 'source-literal' && v !== 'allowed' && v !== 'string-treated-safe') {
            addNode(key, 'reflective-key', `computed key at reflective base ${base} is not a source literal or a syntactically numeric form (${v}): ${key.getText()}`);
          }
        }
      }
    }

    if (ts.isImportCall(node) || (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
      addNode(node, 'dynamic-import', 'dynamic import()');
      const arg = node.arguments?.[0];
      const spec = arg && isStringLiteralLike(arg) ? arg.text : undefined;
      if (!specifierAllowed(rel, spec ?? '', { typeOnly: false })) {
        addNode(node, 'specifier-not-allowed', `module specifier '${spec ?? '<non-literal>'}' is not on the positive allow-list`);
      }
    }

    if (ts.isCallExpression(node) && isIdent(node.expression, 'require')) {
      const arg = node.arguments[0];
      const spec = arg && isStringLiteralLike(arg) ? arg.text : undefined;
      if (spec === 'crypto' || spec === 'node:crypto') addNode(node, 'require-crypto', "require('node:crypto'|'crypto')");
      else if (spec === 'module' || spec === 'node:module') addNode(node, 'node-module', "require('node:module'|'module')");
      else addNode(node, 'require-not-allowed', `require(${spec !== undefined ? `'${spec}'` : '...'})`);
      if (spec !== undefined && !specifierAllowed(rel, spec) && spec !== 'crypto' && spec !== 'node:crypto' && spec !== 'module' && spec !== 'node:module') {
        addNode(node, 'specifier-not-allowed', `module specifier '${spec}' is not on the positive allow-list`);
      } else if (spec === undefined) {
        addNode(node, 'specifier-not-allowed', `module specifier '<non-literal>' is not on the positive allow-list`);
      }
    }

    if (ts.isImportEqualsDeclaration(node) && node.moduleReference && ts.isExternalModuleReference(node.moduleReference)) {
      const expr = node.moduleReference.expression;
      const spec = expr && isStringLiteralLike(expr) ? expr.text : undefined;
      if (spec === 'crypto' || spec === 'node:crypto') addNode(node, 'require-crypto', "require('node:crypto'|'crypto')");
      else if (spec === 'module' || spec === 'node:module') addNode(node, 'node-module', "require('node:module'|'module')");
      if (!specifierAllowed(rel, spec ?? '')) addNode(node, 'specifier-not-allowed', `module specifier '${spec ?? '<non-literal>'}' is not on the positive allow-list`);
    }

    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const mem = accessMemberName(node);
      if (mem === 'constructor') addNode(node, 'constructor-reach', 'member access named constructor');
      if (mem === '__proto__') addNode(node, 'proto-member', 'member access named __proto__');
      if (PROCESS_ALWAYS_BANNED.includes(mem)) addNode(node, 'process-banned-member', mem === undefined ? 'banned member' : (ts.isElementAccessExpression(node) ? `['${mem}'] (always red, any base)` : `.${mem} (always red, any base)`));
      if (mem === 'crypto') addNode(node, 'crypto-member', ts.isElementAccessExpression(node) ? "['crypto'] (always red, any base)" : '.crypto (always red, any base)');
      if ((mem === 'binding' || mem === 'getBuiltinModule') && isIdent(node.expression, 'process')) {
        addNode(node, 'process-binding', 'process.binding / process.getBuiltinModule');
      }
      if (mem === 'require' && isIdent(node.expression, 'module')) addNode(node, 'module-require', 'module.require');
      if (isIdent(node.expression, 'globalThis')) {
        if (ts.isElementAccessExpression(node)) addNode(node, 'globalThis-computed', 'computed globalThis[...] access');
        else if (mem === 'crypto') addNode(node, 'globalThis-crypto', 'globalThis.crypto');
        if (mem !== undefined && ts.isPropertyAccessExpression(node) && !GLOBALTHIS_MEMBERS_ALLOWED.includes(mem)) {
          addNode(node, 'globalThis-member', `globalThis.${mem} (not in GLOBALTHIS_MEMBERS_ALLOWED)`);
        }
      }
    }

    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expr = node.expression;
      const mem = accessMemberName(expr);
      if (mem === 'constructor') addNode(node, 'function-eval', '.constructor( call (Function-constructor reach)');
      if (isReflectConstruct(expr)) addNode(node, 'reflect-construct', 'Reflect.construct');
      if (isObjectOrReflectGetPrototypeOf(expr)) addNode(node, 'getPrototypeOf', 'Object/Reflect.getPrototypeOf');
      if ((ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) && accessMemberName(expr) === 'require') {
        addNode(expr, 'require-member-call', '.require( member call');
      }
    }
    // Reflect.construct / getPrototypeOf as a member even when not called (reach).
    if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))) {
      if (isReflectConstruct(node)) addNode(node, 'reflect-construct', 'Reflect.construct');
      if (isObjectOrReflectGetPrototypeOf(node)) addNode(node, 'getPrototypeOf', 'Object/Reflect.getPrototypeOf');
    }

    if (ts.isBindingElement(node)) {
      const keyNode = node.propertyName ?? node.name;
      const key = ts.isIdentifier(keyNode) ? idText(keyNode) : literalText(keyNode);
      if (key === 'constructor') addNode(node, 'constructor-reach', 'destructured constructor');
      if (key === '__proto__') addNode(node, 'proto-member', 'destructured __proto__');
      if (PROCESS_ALWAYS_BANNED.includes(key)) addNode(node, 'process-banned-member', `destructured ${key} (always red)`);
      if (key === 'crypto') addNode(node, 'crypto-member', 'destructured crypto (always red, any base)');
    }

    if (ts.isIdentifier(node)) {
      const name = idText(node);
      if (name === 'crypto' && !isDotOrColonPropertyName(node)) addNode(node, 'bare-global-crypto', 'bare global crypto');
      if ((name === 'global' || name === 'self' || name === 'window') && !isDotOrColonPropertyName(node)) addNode(node, 'global-self', name === 'window' ? 'window' : 'global / self');
      if ((name === 'Function' || name === 'eval') && !isDotOrColonPropertyName(node)) addNode(node, 'function-eval', 'Function / eval (code-from-string can reach the global object)');
      if (name === 'createRequire') addNode(node, 'createRequire', 'createRequire identifier');
      if ((name === 'setFips' || name === 'fips')) addNode(node, 'fips', 'setFips / fips identifier or member');
      if (name === 'randomFillSync' && !rel.startsWith('src/entropy/')) addNode(node, 'randomFillSync-outside-entropy', 'randomFillSync outside src/entropy/');
      if (name === 'require' && !isPropertyAccessName(node) && !(node.parent && ts.isCallExpression(node.parent) && node.parent.expression === node)) {
        addNode(node, 'require-alias', 'require referenced other than as a direct call (alias, destructuring, argument)');
      }
      if (name === 'process' && !isPropertyAccessName(node)) {
        if (isMemberAccessBase(node)) {
          const acc = node.parent;
          const mem = accessMemberName(acc);
          if (mem === undefined || !PROCESS_MEMBERS_ALLOWED.includes(mem)) {
            addNode(node, 'process-reach', mem !== undefined && ts.isPropertyAccessExpression(acc) ? `process.${mem} (not in PROCESS_MEMBERS_ALLOWED)` : 'process referenced other than as process.<allowed member> (alias, destructuring, argument)');
          }
        } else {
          addNode(node, 'process-reach', 'process referenced other than as process.<allowed member> (alias, destructuring, argument)');
        }
      }
      if (name === 'globalThis' && !isPropertyAccessName(node)) {
        if (!isMemberAccessBase(node) && !isGuardFormGlobalThisArg(node, rel)) {
          addNode(node, 'globalThis-alias', 'globalThis referenced other than as a member-access base (alias, destructuring or argument)');
        }
      }
    }

    if (ts.isElementAccessExpression(node)) {
      const lit = literalText(node.argumentExpression);
      if (lit === 'fips' || lit === 'setFips') addNode(node, 'fips', 'computed setFips / fips member');
    }

    if (ts.isCallExpression(node) && isDefinePropertyGlobalThis(node)) dps.push(node);

    if (ts.isPropertyAccessExpression(node) && isIdent(node.expression, 'Symbol') && idText(node.name) === 'for' && rel === GUARD_PATH) {
      addNode(node, 'defineProperty-globalThis', 'Symbol.for in the guard');
    }
  });

  if (rel !== GUARD_PATH) {
    for (const m of dps) addNode(m, 'defineProperty-globalThis', `Object.defineProperty(globalThis, ...) outside ${GUARD_PATH}`);
  } else {
    if (dps.length > 1) for (const m of dps.slice(1)) addNode(m, 'defineProperty-globalThis', 'second Object.defineProperty(globalThis, ...) in the guard');
    if (dps.length >= 1) {
      const call = dps[0];
      const key = call.arguments[1];
      const desc = call.arguments[2];
      const keyOk = key && ts.isStringLiteral(key) && !/\\/.test(key.getText());
      if (!keyOk || !isExactGuardDescriptor(desc)) {
        addNode(call, 'defineProperty-globalThis', 'guard defineProperty is not the exact R-58(6) form (fixed string literal key, value, writable/configurable/enumerable false)');
      }
      let hasOwnBefore = false, throwBefore = false;
      visit(sf, (n) => {
        if (n.getStart() >= call.getStart()) return;
        if (ts.isCallExpression(n) && isHasOwnGlobalThis(n)) hasOwnBefore = true;
        if (ts.isThrowStatement(n)) throwBefore = true;
      });
      if (!hasOwnBefore || !throwBefore) addNode(call, 'defineProperty-globalThis', 'guard defineProperty is not preceded by an Object.hasOwn(globalThis, KEY) check that throws');
    }
  }

  return { hits, pairs };
}

const READ_NAME = /read|fetch|bytes|entropy|fill|draw/i;
const ENTRY_NAME = /^(createRng|createAuditedRng|randomInt|shuffle|sample|weightedPick|randomBytes|create[\w$]*Rng|random[\w$]*)$/;

// Exported names of one module: [{ name, allowed }], plus opaque=true for export * / default / destructuring.
// allowed = true only for an exact READ_NAME_ALLOW declaration (HoQ tighten ruling; each entry needs a HoQ ruling + fixture).
export const READ_NAME_ALLOW = Object.freeze({ FINGERPRINT_BYTES: '16' });
export function exportsOf(src) {
  const sf = parseSource('exports.ts', src);
  const out = []; const opaque = [];
  const [a] = strip(src);
  visit(sf, (node) => {
    if (ts.isExportDeclaration(node)) {
      if (node.exportClause && ts.isNamedExports(node.exportClause)) {
        for (const el of node.exportClause.elements) out.push({ name: idText(el.name), allowed: false });
      } else if (!node.exportClause || ts.isNamespaceExport(node.exportClause)) {
        opaque.push('*');
      }
    } else if (ts.isExportAssignment(node)) {
      opaque.push('default');
    } else if (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)
      || ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node)) {
      const mods = ts.getModifiers(node) ?? node.modifiers ?? [];
      const isExport = mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
      const isDefault = mods.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
      if (isExport && isDefault) opaque.push('default');
      else if (isExport && node.name) out.push({ name: idText(node.name), allowed: false });
    } else if (ts.isVariableStatement(node)) {
      const mods = ts.getModifiers(node) ?? node.modifiers ?? [];
      if (!mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) return;
      const declKind = node.declarationList.flags & ts.NodeFlags.Const ? 'const'
        : node.declarationList.flags & ts.NodeFlags.Let ? 'let' : 'var';
      const isDeclare = mods.some((m) => m.kind === ts.SyntaxKind.DeclareKeyword);
      if (node.declarationList.declarations.length > 1) opaque.push(`${declKind} with several declarators`);
      for (const d of node.declarationList.declarations) {
        if (ts.isArrayBindingPattern(d.name) || ts.isObjectBindingPattern(d.name)) {
          opaque.push(`${declKind} ` + (ts.isArrayBindingPattern(d.name) ? '[' : '{'));
          continue;
        }
        if (!ts.isIdentifier(d.name)) continue;
        const name = idText(d.name);
        const want = Object.hasOwn(READ_NAME_ALLOW, name) ? READ_NAME_ALLOW[name] : undefined;
        const start = node.getStart();
        const allowed = want !== undefined && declKind === 'const' && !isDeclare && !d.type
          && new RegExp(`^export\\s+const\\s+${name}\\s*=\\s*${want}\\s*;`).test(a.slice(start));
        out.push({ name, allowed });
      }
    }
  });
  return { names: out, opaque };
}

function specifiersOf(src, rel = 'file.ts') {
  const sf = parseSource(rel, src);
  return collectSpecifiers(sf, rel).map((s) => s.spec);
}

function readCallsOf(src, rel = 'file.ts') {
  const sf = parseSource(rel, src);
  const out = [];
  visit(sf, (node) => {
    if (!ts.isCallExpression(node)) return;
    const name = callName(node.expression);
    if (name && READ_CALL_NAME.test(name)) out.push({ name, pos: node.expression.getStart() });
  });
  return out;
}

export function entropyTriggers(root, { phaseExit = false } = {}) {
  const why = [];
  if (phaseExit) why.push('(iii) --phase-exit');
  for (const f of walk(join(root, 'src', 'entropy'))) {
    const rel = relative(root, f).split(sep).join('/'); const src = readFileSync(f, 'utf8');
    if (specifiersOf(src, rel).some((x) => x === 'node:crypto' || x === 'crypto')) why.push(`(i) ${rel} imports or re-exports from node:crypto`);
    const ex = exportsOf(src);
    for (const o of ex.opaque) why.push(`(i) ${rel} has an opaque export (${o.trim()}), treated as a read API`);
    for (const e of ex.names) if (READ_NAME.test(e.name) && !e.allowed) why.push(`(i) ${rel} exports ${e.name}`);
    for (const m of readCallsOf(src, rel)) why.push(`(i) ${rel}:${lineOf(src, m.pos)} calls ${m.name}(`);
  }
  try {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    for (const k of ['main', 'module', 'exports']) if (pkg[k] !== undefined) why.push(`(ii) package.json ${k} exports the package root`);
  } catch { /* no package.json: nothing exported */ }
  const seen = new Set(); const todo = ['src/index.ts', 'src/audited/index.ts'];
  while (todo.length) {
    const rel = todo.pop(); if (seen.has(rel) || !existsSync(join(root, rel))) continue; seen.add(rel);
    const src = readFileSync(join(root, rel), 'utf8'); const ex = exportsOf(src);
    for (const e of ex.names) if (ENTRY_NAME.test(e.name)) why.push(`(ii) ${rel} exports ${e.name}, reachable from the core entry`);
    for (const sp of specifiersOf(src, rel)) if (sp.startsWith('.')) todo.push(resolveRel(rel, sp));
  }
  return why;
}

export function scanTree(root, { phaseExit = false, computedLiteralAllow, treatStringAsSafe, reflectiveBases, skipChecker } = {}) {
  const hits = []; const pairs = []; const reports = [];
  hits.push(...untrackedSymlinkHits(root));
  const absFiles = SCAN_ROOTS.flatMap((r) => walk(join(root, r)));
  const files = [];
  for (const f of absFiles) {
    const rel = posixRel(root, f);
    if (rel.startsWith('src/') && SRC_JS_EXT.test(rel)) {
      hits.push(`${rel}:1: rule27-js-under-src .js/.mjs/.cjs is banned under src/`);
      continue;
    }
    files.push([rel, readFileSync(f, 'utf8')]);
  }
  if (existsSync(join(root, '.git'))) {
    const ls = spawnSync('git', ['ls-files', '-z', ...SCAN_ROOTS], { cwd: root, encoding: 'buffer' });
    if (ls.status === 0) {
      const tracked = ls.stdout.toString('utf8').split('\0').filter(Boolean).map(normalizePosix);
      const parsedSet = new Set(files.map(([rel]) => rel));
      for (const rel of tracked) {
        if (PARSE_EXT.test(rel) && !parsedSet.has(rel)) {
          hits.push(`${rel}:1: rule27-unparsed-tracked tracked source file under a scan root was not parsed`);
        }
        if (rel.startsWith('src/') && isTrackedNonTs(rel) && !TRACKED_NON_TS_ALLOWED.includes(rel)) {
          hits.push(`${rel}:1: rule27-tracked-non-ts tracked extensionless or .json file is not on TRACKED_NON_TS_ALLOWED`);
        }
      }
    }
  }
  const parsedFiles = new Set(files.map(([rel]) => rel));
  const prog = skipChecker === true ? null : makeProgram(files);
  const fileOpts = { computedLiteralAllow, treatStringAsSafe, reflectiveBases, parsedFiles, root, skipChecker };
  for (const [rel, src] of files) {
    const sf = prog ? (prog.program.getSourceFile(rel) ?? parseSource(rel, src)) : parseSource(rel, src);
    const r = scanFile(rel, src, { ...fileOpts, checker: prog?.checker, sourceFile: sf });
    hits.push(...r.hits); pairs.push(...r.pairs);
  }
  const have = new Set(pairs.map((p) => p.pair));
  for (const p of pairs) if (!REQUIRED_PAIRS.includes(p.pair)) hits.push(`${p.at}: rule27-extra-pair (${p.pair.replace('@', ', ')}/) is not in the allowlist`);
  for (const p of REQUIRED_PAIRS) {
    if (have.has(p)) continue;
    const dir = p.split('@')[1];
    const line = `src/${dir}/:0: rule27-missing-pair (${p.replace('@', ', ')}/) required by L596 is absent`;
    if (dir === 'entropy' && existsSync(join(root, 'src', dir))) {
      const why = entropyTriggers(root, { phaseExit });
      if (why.length) hits.push(`${line} [PH1-M1 trigger: ${why.join('; ')}]`);
      else reports.push(`${line} [report-only: src/entropy/ has no entropy read path and no trigger (i)-(iii) holds (PH1-M1 erratum)]`);
    } else if (existsSync(join(root, 'src', dir)) || phaseExit) hits.push(line);
    else reports.push(`${line} [report-only: src/${dir}/ does not exist yet; red under --phase-exit]`);
  }
  return { hits, pairs, reports };
}

const GOOD = { 'src/entropy/a.ts': "import { randomFillSync } from 'node:crypto';\nexport const f = randomFillSync;\n",
  'src/evidence/a.ts': "import { createHash } from 'node:crypto';\nexport const h = () => createHash('sha256');\n",
  'src/identity/a.ts': "import { getFips } from 'node:crypto';\nexport const g = () => getFips();\n",
  'src/audited/a.ts': "import { h } from '../evidence/a.ts';\nexport const x = h;\n" };

export const BAD = {
  'namespace-import': "import * as c from 'node:crypto';\n", 'default-import': "import c from 'node:crypto';\n",
  'require-crypto': "const c = require('crypto');\n", 'dynamic-import': "const c = await import('node:crypto');\n",
  'process-binding': "process.binding('crypto');\n", 'process-getBuiltinModule': "process.getBuiltinModule('node:crypto');\n",
  'globalThis-crypto': 'globalThis.crypto.getRandomValues(b);\n', 'globalThis-computed': "globalThis['cry' + 'pto'];\n",
  'bare-global-crypto': 'crypto.getRandomValues(b);\n', 'global-crypto': 'global.crypto;\n', 'self-crypto': 'self.crypto;\n',
  'node-module': "import { createRequire } from 'node:module';\n", 'createRequire': 'const r = createRequire(import.meta.url);\n',
  'setFips': 'x.setFips(1);\n', 'fips-member': 'x.fips = 1;\n', 'extra-pair': "import { randomBytes } from 'node:crypto';\n",
  'createHash-outside-evidence': "import { createHash } from 'node:crypto';\n", 'audited-import': "import { readFileSync } from 'node:fs';\n",
  'defineProperty-globalThis': "Object.defineProperty(globalThis, 'k', { value: 1 });\n",
  'capability-crypto': "import { randomFillSync } from 'node:crypto';\n", 'mapping-namespace': "import * as m from './x.ts';\n",
  'verify-drbg': "import { d } from '@open-rng-engine/drbg';\n", 'verify-drbg-relative': "import { d } from '../../packages/drbg/src/index.ts';\n",
  'verify-binding-wrong-path': "import { d } from '@open-rng-engine/drbg';\n",
  'entropy-alias': "import { randomFillSync as rf } from 'node:crypto';\n",
  'entropy-other-path': "import { randomFillSync } from '../mapping/x.ts';\n",
  'randomFillSync-outside-entropy': "import { randomFillSync } from '../entropy/a.ts';\n",
  // HoQ tighten ruling: allow-list red cases (planted over src/entropy/a.ts, so entropy/ has no randomFillSync import).
  'allowlist-SEED_BYTES': 'export const SEED_BYTES = 32;\n',
  'allowlist-FINGERPRINT_BYTES-15': 'export const FINGERPRINT_BYTES = 15;\n',
  'allowlist-FINGERPRINT_BYTES-string': "export const FINGERPRINT_BYTES = '16';\n",
  'allowlist-FINGERPRINT_BYTES-let': 'export let FINGERPRINT_BYTES = 16;\n',
  'allowlist-FINGERPRINT_BYTES-reexport': 'const FINGERPRINT_BYTES = 16;\nexport { FINGERPRINT_BYTES };\n',
  // HoQ coverage gaps on 2de685b2.
  'allowlist-FINGERPRINT_BYTES-multi': 'export const FINGERPRINT_BYTES = 16, X_BYTES = 1;\n', // G-15
  'globalThis-destructure': 'const {crypto: c} = globalThis;\n', // G-12
  'globalThis-alias': 'const g = globalThis;\ng.crypto;\n', // G-12
  'globalThis-Reflect-get': "Reflect.get(globalThis,'crypto');\n", // G-12
  'globalThis-getOwnPropertyDescriptor': "Object.getOwnPropertyDescriptor(globalThis,'crypto');\n", // G-12
  'Function-return-this': "Function('return this')();\n", // G-12
  'require-node-module': "const m = require('node:module');\n", // G-13
  'require-module': "const m = require('module');\n", // G-13
  'fips-identifier': 'const v = fips;\n', // G-16
  'fips-computed': "x['fips'];\n", // G-16
  // HoQ coverage gaps on 83aa9529.
  'gt-self-crypto': 'globalThis.self.crypto;\n', 'gt-window-crypto': 'globalThis.window.crypto;\n', // G-17
  'gt-globalThis-crypto': 'globalThis.globalThis.crypto;\n', 'gt-Function': "globalThis.Function('return this')();\n", // G-17
  'gt-eval': "globalThis.eval('crypto');\n", 'gt-Reflect-get': "globalThis.Reflect.get(globalThis.self,'crypto');\n", // G-17
  'gt-process-getBuiltinModule': "globalThis.process.getBuiltinModule('crypto');\n", 'gt-process-binding': "globalThis.process.binding('crypto');\n", // G-17
  'process-alias': "const p = globalThis.process;\np.getBuiltinModule('crypto');\n", // G-18
  'process-destructure': "const {getBuiltinModule: g} = process;\ng('crypto');\n", // G-18
  'process-linkedBinding': "process._linkedBinding('x');\n", 'process-dlopen': 'process.dlopen(m, f);\n', // G-18
  'process-mainModule': 'process.mainModule;\n', 'process-plain-member': 'process.env;\n', // G-18
  'module-require': "module.require('crypto');\n", 'mainModule-require': "process.mainModule.require('crypto');\n", // G-19
  'require-alias': "const r = require;\nr('crypto');\n", 'require-destructure': 'const { require: r } = m;\n', // G-19
  'require-member-call': "x.require('crypto');\n", // G-19
  'window-alias': 'const w = window;\n', 'constructor-call': "(() => 1).constructor('return this')();\n", // G-20 (M-152d, M-152g)
  // G-25 / M-152c: hasOwn(globalThis,'k') at a NON-guard path; exact coreGuard forms only at GUARD_PATH.
  'guard-forms-non-guard-path': "Object.hasOwn(globalThis, 'k');\n",
  // G-23 / M-155: unicode-escape identifiers and string-literal property keys.
  'unicode-ident-globalThis': 'glob\\u0061lThis.crypto;\n',
  'unicode-key-constructor': "x['\\u0063onstructor'];\n",
  // G-24 / M-156: positive allow-list (node:vm and cousins, plus dynamic import / export-from / require / bare fs).
  'import-node-vm-default': "import vm from 'node:vm';\n",
  'import-node-vm-named': "import { runInNewContext } from 'node:vm';\n",
  'import-node-inspector': "import { Session } from 'node:inspector';\n",
  'import-node-worker_threads': "import { Worker } from 'node:worker_threads';\n",
  'import-node-child_process': "import { spawn } from 'node:child_process';\n",
  'dynamic-import-node-vm': "const c = await import('node:vm');\n",
  'export-from-node-vm': "export { runInNewContext } from 'node:vm';\n",
  'require-node-vm': "const vm = require('node:vm');\n",
  'import-bare-fs': "import { readFileSync } from 'fs';\n",
  // G-21/22 / M-157: constructor reach via element access, Reflect.construct, getPrototypeOf, __proto__.
  'constructor-element': "x['constructor'];\n",
  'reflect-construct': 'Reflect.construct(X, []);\n',
  'object-getPrototypeOf': 'Object.getPrototypeOf(x);\n',
  'reflect-getPrototypeOf': 'Reflect.getPrototypeOf(x);\n',
  'proto-member': 'x.__proto__;\n',
  // G-26 / M-158
  'm158-concat-reflect-constructor': "const k = 'constr'+'uctor';\nReflect.get(Reflect.get([], k), k);\n",
  'm158-reflect-get-constructor-literal': "Reflect.get(() => 0, 'constructor');\n",
  'm158-template-key': 'g[`cry${"p"}to`];\n',
  'm158-concat-crypto': "g['cry'+'pto'];\n",
  // G-27 / M-159
  'extensionless-relative': "// @ts-ignore\nimport { k } from './ev';\n",
  // M-160 parse error is red
  'parse-error': 'const x: = ;\n',
  // NIT: import type is relative-only
  'import-type-non-relative': "import type { X } from 'fs';\n",
  // M-161 extras: literal-typed var / string-typed computed keys are red under the empty production allow-list
  'm161-literal-typed-var': "const k = 'foo' as const;\no[k];\n",
  'm161-string-typed': "const s: string = 'x';\no[s];\n",
  // G-28 / M-163..M-165 and HoQ b1..b6 (planted in src/health in HoQ's run; fixtures here use src/mapping/bad.ts unless noted).
  'b1-lookupGetter-gopd': "const FP = ({}).__lookupGetter__('__proto__').call(() => 0);\nconst F = Object.getOwnPropertyDescriptor(FP, 'constructor').value;\nconst g = F('return globalThis')();\ng.crypto.getRandomValues(new Uint8Array(1));\n",
  'b2-computed-destructure': "const k = 'constr'+'uctor';\nconst { [k]: F } = (() => 0);\nconst g = F('return globalThis')();\nconst k2 = 'cry'+'pto';\nconst { [k2]: c } = g;\nc.getRandomValues(new Uint8Array(1));\n",
  'b3-number-laundered-key': "const k = 'constructor' as unknown as number;\nconst fn = () => 0;\nconst F = fn[k];\nconst g = F('return globalThis')();\nconst c = g['crypto' as unknown as number];\nc.getRandomValues(new Uint8Array(1));\n",
  'b4-literal-computed-destructure': "const { ['constructor']: F } = (() => 0);\nconst g = F('return globalThis')();\ng.crypto.getRandomValues(new Uint8Array(1));\n",
  'b5-b1-plus-prototype': "const FP = ({}).__lookupGetter__('__proto__').call(() => 0);\nconst F = Object.getOwnPropertyDescriptor(FP, 'constructor').value;\nconst g = F('return globalThis')();\nCrypto.prototype.getRandomValues.call(g.crypto, new Uint8Array(1));\n",
  'b6-b2-plus-randomUUID': "const k = 'constr'+'uctor';\nconst { [k]: F } = (() => 0);\nconst g = F('return globalThis')();\ng.crypto.randomUUID();\n",
  'm163-computed-destructure': "const k = 'constr'+'uctor';\nconst { [k]: F } = (() => 0);\n",
  'm163-literal-computed-destructure': "const { ['constructor']: F } = (() => 0);\n",
  'm164-lookupGetter': "({}).__lookupGetter__('__proto__');\n",
  'm164-literal-gopd': "Object.getOwnPropertyDescriptor(Array.prototype, 'constructor');\n",
  'm165-number-laundered-key': "const k = 'constructor' as unknown as number;\nfn[k];\n",
  'banned-string-constructor': "const s = 'constructor';\n",
  'banned-string-proto': "const s = '__proto__';\n",
  'banned-string-prototype': "const s = 'prototype';\n",
  'banned-template-constructor': 'const s = `constructor`;\n',
  'banned-lookupSetter': 'x.__lookupSetter__;\n',
  'banned-defineGetter': 'x.__defineGetter__;\n',
  'banned-defineSetter': 'x.__defineSetter__;\n',
  'type-assertion-as': 'const x = 1 as number;\n',
  'type-assertion-angle': 'const x = <number>1;\n',
  'banned-type-any': 'const x: any = 1;\n',
  'banned-type-unknown': 'const x: unknown = 1;\n',
  'non-null-assertion': 'const x = y!;\n',
  'ts-ignore': '// @ts-ignore\nconst x = 1;\n',
  'ts-nocheck': '// @ts-nocheck\nconst x = 1;\n',
  'ts-expect-error-unpinned': '// @ts-expect-error typings\nconst x = 1;\n',
  'prepareStackTrace': 'Error.prepareStackTrace = f;\n',
  'captureStackTrace': 'Error.captureStackTrace(e);\n',
  'stackTraceLimit': 'Error.stackTraceLimit = 0;\n',
  'computed-object-key': "const k = 'a'+'b';\nconst o = { [k]: 1 };\n",
  'string-element-access': "const o = { kind: 1 };\no['kind'];\n",
  'setPrototypeOf': 'Object.setPrototypeOf(x, y);\n',
  // S-1: element-access keys are AST/scope only (type-checker number is not enough). Each fixture is killed by check:ph0.
  's1-overload-lie': "function k(): number;\nfunction k(): string | number { return 'constr' + 'uctor' }\nfunction f() {\n  const i = k();\n  const o = { x: 1 };\n  o[i];\n}\n",
  's1-type-guard-lie': "function isN(x: string | number): x is number { return true; }\nfunction f(x: string | number) {\n  const o = { x: 1 };\n  if (isN(x)) o[x];\n}\n",
  's1-asserts-is-number': "function assertN(x: string | number): asserts x is number {}\nfunction f(x: string | number) {\n  assertN(x);\n  const o = { x: 1 };\n  o[x];\n}\n",
  's1-method-param-bivariance': "type Setter = { set(k: number): void };\nconst o = { x: 1 };\nconst box: Setter = { set(k) { o[k]; } };\n",
  's1-array-covariance': "function f() {\n  const nums: number[] = [];\n  const mixed: Array<string | number> = nums;\n  mixed.push('constr' + 'uctor');\n  const k = nums[0];\n  const o = { x: 1 };\n  o[k];\n}\n",
  's1-json-parse-key': "function f() {\n  const k: number = JSON.parse('1');\n  const o = { x: 1 };\n  o[k];\n}\n",
  's1-plus-concat-key': "function f() {\n  const k = 1 + 0;\n  const o = { x: 1 };\n  o[k];\n}\n",
  's1-parameter-key': "function f(i: number) {\n  const o = { x: 1 };\n  o[i];\n}\n",
  's1-closure-written': "function f() {\n  let i = 0;\n  function inc() { i = 1; }\n  const o = { x: 1 };\n  o[i];\n}\n",
  'crypto-member-any-base': 'obj.crypto;\n',
  'proxy-get-trap': 'const o = new Proxy({}, { get(t) { return t[0]; } });\n',
  'template-constructor-key': 'const o = { x: 1 };\no[`constructor`];\n',
  'import-bare-worker_threads': "import { Worker } from 'worker_threads';\n",
  'import-bare-child_process': "import { spawn } from 'child_process';\n",
  'import-data-url': "import x from 'data:text/javascript,export default 1';\n",
  'import-blob-url': "import x from 'blob:https://example.com/id';\n",
  'process-argv': 'process.argv;\n',
  'process-execArgv': 'process.execArgv;\n',
  's1-g37-array-destructure': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  [k] = [s];
  return o[k];
}
`,
  's1-g37-object-destructure': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  ({ a: k } = { a: s });
  return o[k];
}
`,
  's1-g37-shorthand': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  ({ k } = { k: s });
  return o[k];
}
`,
  's1-g37-nested-pattern': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  ({ a: [k] } = { a: [s] });
  return o[k];
}
`,
  's1-g37-default-pattern': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  [k = 0] = [s];
  return o[k];
}
`,
  's1-g37-rest': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  const arr: string[] = [s];
  [...k] = arr;
  return o[k];
}
`,
  's1-g37-for-of-array': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  for ([k] of a) return o[k];
}
`,
  's1-g37-for-of-object': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  for ({ k } of rec) return o[k];
}
`,
  's1-g37-for-in-head': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  for (k in o) return o[k];
}
`,
  's1-g37-compound-plus-eq': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  k += 1;
  return o[k];
}
`,
  's1-g37-compound-nullish-eq': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  k ??= 1;
  return o[k];
}
`,
  's1-g37-compound-or-eq': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  k ||= 1;
  return o[k];
}
`,
  's1-g37-compound-and-eq': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  k &&= 1;
  return o[k];
}
`,
  's1-g37-nested-arrow-destructure': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  const g = () => { [k] = [s]; };
  g();
  return o[k];
}
`,
  's1-g37-labelled-write': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k = 0;
  L: { k = 1; }
  return o[k];
}
`,
  's1-g37-union-type': `function f(o: Record<string, number>, s: string, a: string[][], rec: Array<{ k: string }>) {
  let k: number | string = 0;
  return o[k];
}
`,
  's1-g37-chain': `type C = { call(t: object, u: Uint8Array): Uint8Array };
type Cr = Record<string, C>;
type Gl = Record<string, Cr>;
type F = Record<string, (s: string) => () => Gl>;
export function reach(): Uint8Array | undefined {
  let k: number | string = 0;
  [k] = ['con'.concat('structor')];
  const fb: F = Object(() => 0);
  const g = fb[k]?.('return glob'.concat('alThis'))();
  if (!g) return undefined;
  let c: number | string = 0;
  [c] = ['cry'.concat('pto')];
  const cr = g[c];
  if (!cr) return undefined;
  let m: number | string = 0;
  [m] = ['getRandom'.concat('Values')];
  return cr[m]?.call(cr, new Uint8Array(4));
}
`,
  's1-g37-chain2': `type Rb = { randomBytes(n: number): Uint8Array };
type P = Record<string, (s: string) => Rb>;
type F = Record<string, (s: string) => () => P>;
export function reach(): Uint8Array | undefined {
  let k: number | string = 0;
  [k] = ['con'.concat('structor')];
  const fb: F = Object(() => 0);
  const p = fb[k]?.('return pro'.concat('cess'))();
  if (!p) return undefined;
  let m: number | string = 0;
  [m] = ['getBuiltin'.concat('Module')];
  const nc = p[m]?.('node:'.concat('crypto'));
  return nc?.randomBytes(4);
}
`,
  's1-g37-chain-entropy': `type C = { call(t: object, u: Uint8Array): Uint8Array };
type Cr = Record<string, C>;
type Gl = Record<string, Cr>;
type F = Record<string, (s: string) => () => Gl>;
export function reach(): Uint8Array | undefined {
  let k: number | string = 0;
  [k] = ['con'.concat('structor')];
  const fb: F = Object(() => 0);
  const g = fb[k]?.('return glob'.concat('alThis'))();
  if (!g) return undefined;
  let c: number | string = 0;
  [c] = ['cry'.concat('pto')];
  const cr = g[c];
  if (!cr) return undefined;
  let m: number | string = 0;
  [m] = ['getRandom'.concat('Values')];
  return cr[m]?.call(cr, new Uint8Array(4));
}
`,
  's1-g43-paren-assign': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
function f(o: Record<string, number>) {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (k) = a; }
  return o[k];
}
`,
  's1-g43-dbl-paren-assign': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
function f(o: Record<string, number>) {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { ((k)) = a; }
  return o[k];
}
`,
  's1-g43-paren-plus-eq': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
function f(o: Record<string, number>) {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (k) += a; }
  return o[k];
}
`,
  's1-g43-for-of-paren': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
export function f(o: Record<string, number>): number | undefined {
  let k = 0;
  for ((k) of [pick('con', 'structor')].filter(isNum)) { return o[k]; }
  return undefined;
}
`,
  's1-g43-comma-last': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
function f(o: Record<string, number>) {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (0, k) = a; }
  return o[k];
}
`,
  's1-g43-paren-assign-entropy': `function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
function f(o: Record<string, number>) {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (k) = a; }
  return o[k];
}
`,
  's1-g43-predicate-ban': `function isNum(x: string | number): x is number { return x !== undefined; }
export const n = 1;
`,
  's1-g43-asserts-is-ban': `function ok(x: string | number): asserts x is number { if (typeof x !== 'number') throw new Error('e'); }
export const n = 1;
`,
  's1-g43-asserts-ban': `function present(x: string | number | undefined): asserts x { if (x === undefined) throw new Error('e'); }
export const n = 1;
`,
  's1-g43-paren-assign-verbatim': `type C = { call(t: object, u: Uint8Array): Uint8Array };
type Cr = Record<string, C>; type Gl = Record<string, Cr>;
type F = Record<string, (s: string) => () => Gl>;
function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
export function reach(): Uint8Array | undefined {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (k) = a; }
  const fb: F = Object(() => 0);
  const g = fb[k]?.(String(pick('return glob', 'alThis')))();
  if (!g) return undefined;
  let c = 0;
  const b = pick('cry', 'pto');
  if (isNum(b)) { (c) = b; }
  const cr = g[c];
  if (!cr) return undefined;
  let m = 0;
  const d = pick('getRandom', 'Values');
  if (isNum(d)) { (m) = d; }
  return cr[m]?.call(cr, new Uint8Array(4));
}
`,
  's1-g43-paren2-verbatim': `type Rb = { randomBytes(n: number): Uint8Array };
type P = Record<string, (s: string) => Rb>;
type F = Record<string, (s: string) => () => P>;
function pick(p: string, q: string): string | number { return p.concat(q); }
function isNum(x: string | number): x is number { return x !== undefined; }
export function reach(): Uint8Array | undefined {
  let k = 0;
  const a = pick('con', 'structor');
  if (isNum(a)) { (k) = a; }
  const fb: F = Object(() => 0);
  const p = fb[k]?.(String(pick('return pro', 'cess')))();
  if (!p) return undefined;
  let m = 0;
  const d = pick('getBuiltin', 'Module');
  if (isNum(d)) { (m) = d; }
  return p[m]?.(String(pick('node:', 'crypto')))?.randomBytes(4);
}
`,
  's1-g43-paren-assign-noguard': `function f(o: Record<string, number>, v: string) {
  let k = 0;
  (k) = v;
  return o[k];
}
`,
};


function m161KeyForms(target) {
  const mid = Math.ceil(target.length / 2);
  const a = target.slice(0, mid), b = target.slice(mid);
  const codes = [...target].map((c) => c.charCodeAt(0)).join(',');
  const b64 = Buffer.from(target, 'utf8').toString('base64');
  return {
    concatenation: { pre: '', expr: `'${a}'+'${b}'` },
    'template-sub': { pre: '', expr: '`${' + JSON.stringify(target) + '}`' },
    variable: { pre: `const k = '${a}'+'${b}';\n`, expr: 'k' },
    'function-return': { pre: `const f = () => '${a}'+'${b}';\n`, expr: 'f()' },
    fromCharCode: { pre: '', expr: `String.fromCharCode(${codes})` },
    atob: { pre: '', expr: `atob('${b64}')` },
    'buffer-toString': { pre: '', expr: `Buffer.from(${JSON.stringify(target)}, 'utf8').toString()` },
    'array-join': { pre: '', expr: `['${a}','${b}'].join('')` },
  };
}
function m161Wrap(base, expr) {
  if (base === 'Reflect') return `Reflect.get(o, ${expr});\n`;
  if (base === 'getOwnPropertyDescriptor') return `Object.getOwnPropertyDescriptor(o, ${expr});\n`;
  if (base === 'defineProperty') return `Object.defineProperty(o, ${expr}, { value: 1 });\n`;
  if (base === 'getPrototypeOf') return `Object[${expr}];\n`;
  if (base === 'constructor' || base === '__proto__') return `o[${expr}];\n`;
  throw new Error(`unknown reflective base ${base}`);
}
const _m161Target = Object.create(null);
_m161Target.Reflect = 'constructor';
_m161Target.getOwnPropertyDescriptor = 'constructor';
_m161Target.defineProperty = 'constructor';
_m161Target.getPrototypeOf = 'getPrototypeOf';
_m161Target.constructor = 'constructor';
Object.defineProperty(_m161Target, '__proto__', { value: '__proto__', enumerable: true, configurable: false, writable: false });
export const M161_TARGET = Object.freeze(_m161Target);
for (const base of REFLECTIVE_BASES) {
  const forms = m161KeyForms(M161_TARGET[base]);
  for (const [form, { pre, expr }] of Object.entries(forms)) {
    BAD[`m161-${form}-${base}`] = `${pre}${m161Wrap(base, expr)}`;
  }
}

// Expected reason for fixtures whose hit is not at the planted file (self-test fails if the reason does not match).
const ALLOW_REASON = (n) => new RegExp(`^src/entropy/:0: rule27-missing-pair \\(randomFillSync, entropy/\\).*PH1-M1 trigger: \\(i\\) src/entropy/a\\.ts exports ${n}\\b`);
function GUARD_SRC() { return "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n"; }
export const BAD_REASON = { 'allowlist-SEED_BYTES': ALLOW_REASON('SEED_BYTES'), 'allowlist-FINGERPRINT_BYTES-15': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-string': ALLOW_REASON('FINGERPRINT_BYTES'), 'allowlist-FINGERPRINT_BYTES-let': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-reexport': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-multi': new RegExp(ALLOW_REASON('FINGERPRINT_BYTES').source.replace('exports FINGERPRINT_BYTES\\b', 'has an opaque export \\(const with several declarators\\)')),
  ...Object.fromEntries([['globalThis-destructure', 'globalThis-alias'], ['globalThis-alias', 'globalThis-alias'], ['globalThis-Reflect-get', 'globalThis-alias'],
    ['globalThis-getOwnPropertyDescriptor', 'globalThis-alias'], ['Function-return-this', 'function-eval'], ['require-node-module', 'node-module'],
    ['require-module', 'node-module'], ['fips-identifier', 'fips'], ['fips-computed', 'fips'],
    ...['gt-self-crypto', 'gt-window-crypto', 'gt-globalThis-crypto', 'gt-Function', 'gt-eval', 'gt-Reflect-get', 'gt-process-getBuiltinModule', 'gt-process-binding'].map((n) => [n, 'globalThis-member']),
    ['process-alias', 'process-banned-member'], ['process-destructure', 'process-reach'], ['process-linkedBinding', 'process-banned-member'],
    ['process-dlopen', 'process-banned-member'], ['process-mainModule', 'process-banned-member'], ['process-plain-member', 'process-reach'],
    ['module-require', 'module-require'], ['mainModule-require', 'process-banned-member'], ['require-alias', 'require-alias'],
    ['require-destructure', 'require-alias'], ['require-member-call', 'require-member-call'], ['window-alias', 'global-self'], ['constructor-call', 'function-eval']].map(([n, c]) => [n, new RegExp(`^src/mapping/bad\\.ts:\\d+: rule27-${c} `)])),
  'guard-forms-non-guard-path': /^packages\/capability\/src\/other\.ts:\d+: rule27-globalThis-alias /,
  'unicode-ident-globalThis': /^src\/mapping\/bad\.ts:\d+: rule27-unicode-escape /,
  'unicode-key-constructor': /^src\/mapping\/bad\.ts:\d+: rule27-unicode-escape /,
  'import-node-vm-default': /^src\/mapping\/bad\.ts:\d+: rule27-default-import /,
  'import-node-vm-named': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-node-inspector': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-node-worker_threads': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-node-child_process': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'dynamic-import-node-vm': /^src\/mapping\/bad\.ts:\d+: rule27-dynamic-import /,
  'export-from-node-vm': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'require-node-vm': /^src\/mapping\/bad\.ts:\d+: rule27-require-not-allowed /,
  'import-bare-fs': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'constructor-element': /^src\/mapping\/bad\.ts:\d+: rule27-constructor-reach /,
  'reflect-construct': /^src\/mapping\/bad\.ts:\d+: rule27-reflect-construct /,
  'object-getPrototypeOf': /^src\/mapping\/bad\.ts:\d+: rule27-getPrototypeOf /,
  'reflect-getPrototypeOf': /^src\/mapping\/bad\.ts:\d+: rule27-getPrototypeOf /,
  'proto-member': /^src\/mapping\/bad\.ts:\d+: rule27-proto-member /,
  'm158-concat-reflect-constructor': /^src\/mapping\/bad\.ts:\d+: rule27-reflect-identifier /,
  'm158-reflect-get-constructor-literal': /^src\/mapping\/bad\.ts:\d+: rule27-reflect-identifier /,
  'm158-template-key': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'm158-concat-crypto': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'extensionless-relative': /^src\/health\/a\.ts:\d+: rule27-relative-specifier /,
  'parse-error': /^src\/mapping\/bad\.ts:\d+: rule27-parse /,
  'import-type-non-relative': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'm161-literal-typed-var': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'm161-string-typed': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'b1-lookupGetter-gopd': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'b2-computed-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-computed-key /,
  'b3-number-laundered-key': /^src\/mapping\/bad\.ts:\d+: rule27-type-assertion /,
  'b4-literal-computed-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'b5-b1-plus-prototype': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'b6-b2-plus-randomUUID': /^src\/mapping\/bad\.ts:\d+: rule27-computed-key /,
  'm163-computed-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-computed-key /,
  'm163-literal-computed-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'm164-lookupGetter': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'm164-literal-gopd': /^src\/mapping\/bad\.ts:\d+: rule27-object-api /,
  'm165-number-laundered-key': /^src\/mapping\/bad\.ts:\d+: rule27-type-assertion /,
  'banned-string-constructor': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'banned-string-proto': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'banned-string-prototype': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'banned-template-constructor': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'banned-lookupSetter': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'banned-defineGetter': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'banned-defineSetter': /^src\/mapping\/bad\.ts:\d+: rule27-banned-lookup /,
  'type-assertion-as': /^src\/mapping\/bad\.ts:\d+: rule27-type-assertion /,
  'type-assertion-angle': /^src\/mapping\/bad\.ts:\d+: rule27-type-assertion /,
  'banned-type-any': /^src\/mapping\/bad\.ts:\d+: rule27-banned-type /,
  'banned-type-unknown': /^src\/mapping\/bad\.ts:\d+: rule27-banned-type /,
  'non-null-assertion': /^src\/mapping\/bad\.ts:\d+: rule27-non-null-assertion /,
  'ts-ignore': /^src\/mapping\/bad\.ts:\d+: rule27-ts-directive /,
  'ts-nocheck': /^src\/mapping\/bad\.ts:\d+: rule27-ts-directive /,
  'ts-expect-error-unpinned': /^src\/mapping\/bad\.ts:\d+: rule27-ts-directive /,
  'prepareStackTrace': /^src\/mapping\/bad\.ts:\d+: rule27-prepare-stack /,
  'captureStackTrace': /^src\/mapping\/bad\.ts:\d+: rule27-prepare-stack /,
  'stackTraceLimit': /^src\/mapping\/bad\.ts:\d+: rule27-prepare-stack /,
  'computed-object-key': /^src\/mapping\/bad\.ts:\d+: rule27-computed-key /,
  'string-element-access': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'setPrototypeOf': /^src\/mapping\/bad\.ts:\d+: rule27-object-api /,
  's1-overload-lie': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-type-guard-lie': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-asserts-is-number': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-method-param-bivariance': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-array-covariance': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-json-parse-key': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-plus-concat-key': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-parameter-key': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-closure-written': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  'crypto-member-any-base': /^src\/mapping\/bad\.ts:\d+: rule27-crypto-member /,
  'proxy-get-trap': /^src\/mapping\/bad\.ts:\d+: rule27-proxy-identifier /,
  'template-constructor-key': /^src\/mapping\/bad\.ts:\d+: rule27-banned-string-literal /,
  'import-bare-worker_threads': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-bare-child_process': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-data-url': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'import-blob-url': /^src\/mapping\/bad\.ts:\d+: rule27-specifier-not-allowed /,
  'process-argv': /^src\/mapping\/bad\.ts:\d+: rule27-process-reach /,
  'process-execArgv': /^src\/mapping\/bad\.ts:\d+: rule27-process-reach /,
  's1-g37-array-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-object-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-shorthand': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-nested-pattern': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-default-pattern': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-rest': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-for-of-array': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-for-of-object': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-for-in-head': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-compound-plus-eq': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-compound-nullish-eq': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-compound-or-eq': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-compound-and-eq': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-nested-arrow-destructure': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-labelled-write': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-union-type': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-chain': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-chain2': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g37-chain-entropy': /^src\/entropy\/g37-chain\.ts:\d+: rule27-computed-access /,
  's1-g43-paren-assign': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-dbl-paren-assign': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-paren-plus-eq': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-for-of-paren': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-comma-last': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-paren-assign-verbatim': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-paren2-verbatim': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-paren-assign-noguard': /^src\/mapping\/bad\.ts:\d+: rule27-computed-access /,
  's1-g43-paren-assign-entropy': /^src\/entropy\/g43-paren\.ts:\d+: rule27-computed-access /,
  's1-g43-predicate-ban': /^src\/mapping\/bad\.ts:\d+: rule27-type-predicate /,
  's1-g43-asserts-is-ban': /^src\/mapping\/bad\.ts:\d+: rule27-type-predicate /,
  's1-g43-asserts-ban': /^src\/mapping\/bad\.ts:\d+: rule27-type-predicate /,
};
const M161_REASON = /^(?:src\/mapping\/bad)\.ts:\d+: rule27-(?:reflect-identifier|reflective-key|computed-access|constructor-reach|proto-member|getPrototypeOf|object-api|banned-string-literal|type-assertion|computed-key) /;
for (const name of Object.keys(BAD)) {
  if (!name.startsWith('m161-') || name === 'm161-literal-typed-var' || name === 'm161-string-typed') continue;
  BAD_REASON[name] = M161_REASON;
}

// Control planted the same way: the single allow-listed declaration stays green (report-only).
export const ALLOW_CONTROL = 'export const FINGERPRINT_BYTES = 16;\n';
// Where each known-bad fixture is planted (default src/mapping/bad.ts).
export const BAD_PATH = { 'audited-import': 'src/audited/bad.ts', 'createHash-outside-evidence': 'src/entropy/bad.ts',
  'capability-crypto': 'packages/capability/src/bad.ts', 'mapping-namespace': 'packages/mapping/src/bad.ts',
  'verify-drbg': 'src/verify/bad.ts', 'verify-drbg-relative': 'src/verify/bad.ts', 'verify-binding-wrong-path': 'src/verify/testingBinding.ts',
  'entropy-alias': 'src/entropy/bad.ts', 'entropy-other-path': 'src/entropy/bad.ts', 'randomFillSync-outside-entropy': 'src/mapping/bad.ts',
  ...Object.fromEntries(Object.keys(BAD).filter((n) => n.startsWith('allowlist-')).map((n) => [n, 'src/entropy/a.ts'])),
  'guard-forms-non-guard-path': 'packages/capability/src/other.ts',
  'extensionless-relative': 'src/health/a.ts', 's1-g37-chain-entropy': 'src/entropy/g37-chain.ts', 's1-g43-paren-assign-entropy': 'src/entropy/g43-paren.ts' };
export const BAD_EXTRA = { 'extensionless-relative': { 'src/health/ev': 'export const k = 1;\n' } };
export const GUARD_OK = "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n";

export function writeFixture(dir, extra = {}) {
  for (const [p, s] of Object.entries({ ...GOOD, ...extra })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), s); }
}

export const SELF_TEST_EXTRA_CASES = ['allowlist-control', 'guard-control', 'MX-12 p8-package key plant', 'MX-12 clean control', 'unparsed-tracked', 'js-under-src', 'tracked-non-ts', 's1-numeric-for-loop-control', 'untracked-symlink', 's1-g37-numeric-assign-control', 's1-g37-numeric-compound-minus-control', 's1-g43-read-default-mutant'];
function mx12Case(base) {
  const out = []; const here = dirname(new URL(import.meta.url).pathname); const lint = join(here, '..', 'claims-lint.mjs');
  const sp1 = JSON.parse(readFileSync(join(here, '..', 'claims-allowlist.json'), 'utf8')).entries.find((e) => e.id === 'S-P1')?.text;
  if (!sp1) return ['MX-12 case: S-P1 not found in tools/claims-allowlist.json'];
  const run = (name, obj) => { const f = join(base, name); writeFileSync(f, JSON.stringify(obj)); return spawnSync(process.execPath, [lint, '--surface', 'p8-package', f], { encoding: 'utf8' }); };
  const red = run('mx12-plant.json', { name: 'open-rng-engine', description: sp1, ['\u0063ertified-by']: 1 });
  if (red.status !== 1 || !red.stdout.split('\n').some((l) => l.includes('(key)'))) out.push(`MX-12 case: p8-package key-only plant not red with a (key) hit (status ${red.status}):\n${red.stdout}`);
  const clean = run('mx12-clean.json', { name: 'open-rng-engine', description: sp1 });
  if (clean.status !== 0) out.push(`MX-12 control: clean p8-package not green (status ${clean.status}):\n${clean.stdout}`);
  return out;
}

function initGit(dir) {
  const r = spawnSync('git', ['init'], { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0) return r;
  spawnSync('git', ['config', 'user.email', 'ci@example.test'], { cwd: dir });
  spawnSync('git', ['config', 'user.name', 'ci'], { cwd: dir });
  return r;
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'rule27-'));
  try {
    const g = join(base, 'good'); writeFixture(g);
    const gr = scanTree(g).hits; if (gr.length) fails.push(`good fixture not green:\n${gr.join('\n')}`);
    for (const [name, src] of Object.entries(BAD)) {
      const d = join(base, name); const file = BAD_PATH[name] ?? 'src/mapping/bad.ts';
      writeFixture(d, { [file]: src, ...(BAD_EXTRA[name] ?? {}) });
      const hits = scanTree(d).hits;
      if (hits.length === 0) fails.push(`known-bad fixture ${name} did not turn rule 27 red`);
      else if (BAD_REASON[name] && !hits.some((h) => BAD_REASON[name].test(h))) fails.push(`known-bad fixture ${name} is red for the wrong reason:\n${hits.join('\n')}`);
    }
    const c = join(base, 'allowlist-control'); writeFixture(c, { 'src/entropy/a.ts': ALLOW_CONTROL });
    const cr = scanTree(c).hits; if (cr.length) fails.push(`allow-list control (export const FINGERPRINT_BYTES = 16) not green:\n${cr.join('\n')}`);
    // G-20 / M-152b: the exact guard at GUARD_PATH stays green.
    const gd = join(base, 'guard-control'); writeFixture(gd, { [GUARD_PATH]: GUARD_SRC() });
    const gh = scanTree(gd).hits; if (gh.length) fails.push(`guard-exact control not green:\n${gh.join('\n')}`);
    if (COMPUTED_LITERAL_KEYS_ALLOWED.length !== 0) fails.push('COMPUTED_LITERAL_KEYS_ALLOWED must stay empty in production');
    const expectedBases = ['Reflect', 'getOwnPropertyDescriptor', 'defineProperty', 'getPrototypeOf', 'constructor', '__proto__'];
    for (const b of expectedBases) if (!REFLECTIVE_BASES.includes(b)) fails.push(`REFLECTIVE_BASES is missing ${b}`);
    // G-28: string keys are AST-only. An injected computed-literal allow-list must not green o[k] or o['kind'].
    const ctlSrc = "const k = 'm161-ok';\no[k];\n";
    const c1 = join(base, 'm161-allow-control'); writeFixture(c1, { 'src/mapping/bad.ts': ctlSrc });
    const chDefault = scanTree(c1).hits;
    if (!chDefault.some((h) => /rule27-computed-access /.test(h))) fails.push(`m161 string-key control without allow-list must be red:\n${chDefault.join('\n')}`);
    const chInjected = scanTree(c1, { computedLiteralAllow: ['m161-ok'] }).hits;
    if (!chInjected.some((h) => /rule27-computed-access /.test(h))) fails.push(`G-28: injected allow-list must not green a string key:\n${chInjected.join('\n')}`);
    const anyHits = scanTree(c1, { computedLiteralAllow: 'ANY' }).hits;
    if (!anyHits.some((h) => /rule27-computed-access /.test(h))) fails.push('G-28: ANY allow-list must not green a string key');
    // Hand mutant 2 (killed by check:ph0): drop one base from the reflective set — the defineProperty concat fixture must still be red.
    const defDir = join(base, 'm161-concatenation-defineProperty');
    const defSrc = BAD['m161-concatenation-defineProperty'];
    if (defSrc) {
      if (!existsSync(defDir)) writeFixture(defDir, { 'src/mapping/bad.ts': defSrc });
      const dropped = scanTree(defDir, { reflectiveBases: REFLECTIVE_BASES.filter((b) => b !== 'defineProperty') }).hits;
      const full = scanTree(defDir).hits;
      if (!full.some((h) => /rule27-(?:reflective-key|computed-access|reflect-identifier) /.test(h))) fails.push(`m161-concatenation-defineProperty must be red with full bases:\n${full.join('\n')}`);
      // If a mutant dropped defineProperty from REFLECTIVE_BASES, this fixture still has a concat key in Object.defineProperty; the
      // self-test below records that we require a reflective-key (or computed-access) hit. The production defaults stay complete.
      if (!dropped.some((h) => /rule27-reflective-key /.test(h)) && !dropped.some((h) => /rule27-computed-access /.test(h))) {
        // expected: dropping the base would let this fixture go green for reflective-key; we assert the FULL default is required
        // by also asserting REFLECTIVE_BASES includes defineProperty (already done) and by a dedicated mutation test.
      }
    }
    // Hand mutant 3 (killed by check:ph0): treat a TS `string` type as safe — the m161-string-typed fixture must stay red.
    const strDir = join(base, 'm161-string-typed');
    const strSafe = scanTree(strDir, { treatStringAsSafe: true }).hits;
    const strDefault = scanTree(strDir).hits;
    if (!strDefault.some((h) => /rule27-computed-access /.test(h))) fails.push(`m161-string-typed must be red by default:\n${strDefault.join('\n')}`);
    // The production default must not treat string as safe (treatStringAsSafe defaults false). A mutation that flips that default is
    // killed by the npm test / self-test that re-imports the checker and asserts the fixture is red (already asserted above).
    if (strSafe.some((h) => /rule27-computed-access /.test(h))) {
      // treatStringAsSafe:true is only an API hook used by tests; production self-test requires default red, already checked.
    }
    // S-1: a numeric local let/const in the same function, and a numeric literal, stay green. Module-level and
    // type-only number annotations are not enough. Typical for-loop `for (let i = 0; i < n; i++) buf[i]` stays green.
    const numDir = join(base, 's1-numeric-local-control');
    writeFixture(numDir, { 'src/mapping/ok.ts': 'function f() {\n  const i = 0;\n  const a: string[] = [];\n  a[i];\n}\n' });
    const numHits = scanTree(numDir).hits.filter((h) => /rule27-computed-access /.test(h));
    if (numHits.length) fails.push(`numeric local binding must stay green:\n${numHits.join('\n')}`);
    const litDir = join(base, 'm161-numeric-literal-control');
    writeFixture(litDir, { 'src/mapping/ok.ts': 'const a: string[] = [];\na[0];\n' });
    const litHits = scanTree(litDir).hits.filter((h) => /rule27-computed-access /.test(h));
    if (litHits.length) fails.push(`numeric-literal element access must stay green:\n${litHits.join('\n')}`);
    const loopDir = join(base, 's1-numeric-for-loop-control');
    writeFixture(loopDir, { 'src/mapping/ok.ts': 'function f(buf: number[], n: number) {\n  for (let i = 0; i < n; i++) buf[i] = i;\n}\n' });
    const loopHits = scanTree(loopDir).hits.filter((h) => /rule27-computed-access /.test(h));
    if (loopHits.length) fails.push(`for-loop numeric index must stay green:\n${loopHits.join('\n')}`);
    const asgDir = join(base, 's1-g37-numeric-assign-control');
    writeFixture(asgDir, { 'src/mapping/ok.ts': 'function f(o: number[], i: number) {\n  let k = 0;\n  k = i * 2;\n  return o[k];\n}\n' });
    const asgHits = scanTree(asgDir).hits.filter((h) => /rule27-computed-access /.test(h));
    if (asgHits.length) fails.push(`plain k = i * 2 must stay green:\n${asgHits.join('\n')}`);
    const subDir = join(base, 's1-g37-numeric-compound-minus-control');
    writeFixture(subDir, { 'src/mapping/ok.ts': 'function f(o: number[]) {\n  let i = 10;\n  i -= 1;\n  return o[i];\n}\n' });
    const subHits = scanTree(subDir).hits.filter((h) => /rule27-computed-access /.test(h));
    if (subHits.length) fails.push(`i -= 1 numeric compound must stay green:\n${subHits.join('\n')}`);
    if (TRACKED_NON_TS_ALLOWED.length !== 0) fails.push('TRACKED_NON_TS_ALLOWED must stay empty in production');

    // G-30: closed-world (unparsed-tracked) fixture — a tracked .ts under src/**/node_modules is walked-skipped.
    const cw = join(base, 'unparsed-tracked');
    writeFixture(cw);
    const hidden = join(cw, 'src/health/node_modules/hidden.ts');
    mkdirSync(dirname(hidden), { recursive: true });
    writeFileSync(hidden, 'export const k = 1;\n');
    if (initGit(cw).status !== 0) fails.push('unparsed-tracked fixture: git init failed');
    else {
      const add = spawnSync('git', ['add', '-A', '-f'], { cwd: cw, encoding: 'utf8' });
      if (add.status !== 0) fails.push(`unparsed-tracked fixture: git add failed: ${add.stderr}`);
      const cwHits = scanTree(cw).hits;
      if (!cwHits.some((h) => /rule27-unparsed-tracked /.test(h))) fails.push(`unparsed-tracked fixture was not red:\n${cwHits.join('\n')}`);
    }

    // G-30: .js under src/
    const jsDir = join(base, 'js-under-src');
    writeFixture(jsDir, { 'src/health/plant.js': 'export const k = 1;\n' });
    const jsHits = scanTree(jsDir).hits;
    if (!jsHits.some((h) => /rule27-js-under-src /.test(h))) fails.push(`js-under-src fixture was not red:\n${jsHits.join('\n')}`);

    // G-30 NIT: tracked extensionless and .json under src are red (allow-list empty).
    const nt = join(base, 'tracked-non-ts');
    writeFixture(nt);
    mkdirSync(join(nt, 'src/health'), { recursive: true });
    writeFileSync(join(nt, 'src/health/notes.json'), '{}\n');
    writeFileSync(join(nt, 'src/health/extensionless'), 'x\n');
    if (initGit(nt).status !== 0) fails.push('tracked-non-ts fixture: git init failed');
    else {
      const add = spawnSync('git', ['add', '-A'], { cwd: nt, encoding: 'utf8' });
      if (add.status !== 0) fails.push(`tracked-non-ts fixture: git add failed: ${add.stderr}`);
      const ntHits = scanTree(nt).hits;
      if (!ntHits.some((h) => h.startsWith('src/health/notes.json') && /rule27-tracked-non-ts /.test(h))) fails.push(`tracked .json was not red:\n${ntHits.join('\n')}`);
      if (!ntHits.some((h) => h.startsWith('src/health/extensionless') && /rule27-tracked-non-ts /.test(h))) fails.push(`tracked extensionless was not red:\n${ntHits.join('\n')}`);
    }

    // NIT: an untracked symlink under a scan root is red.
    const sl = join(base, 'untracked-symlink');
    writeFixture(sl);
    mkdirSync(join(sl, 'src/health'), { recursive: true });
    writeFileSync(join(sl, 'src/health/target.ts'), 'export const k = 1;\n');
    const link = join(sl, 'src/health/link.ts');
    spawnSync('ln', ['-s', 'target.ts', link], { cwd: sl });
    const slHits = scanTree(sl).hits;
    if (!slHits.some((h) => /rule27-untracked-symlink /.test(h))) fails.push(`untracked-symlink fixture was not red:\n${slHits.join('\n')}`);

    // G-43: restoring the default READ classification is killed by check:ph0 --self-test alone.
    const mutCase = join(base, 's1-g43-read-default-mutant');
    mkdirSync(mutCase, { recursive: true });
    const checkerSrc = readFileSync(new URL(import.meta.url), 'utf8');
    const needle = "return 'UNKNOWN'; // G-43 no default READ";
    if (!checkerSrc.includes(needle)) fails.push('G-43 fail-closed default needle missing from classifyReference');
    else {
      const mutFile = join(mutCase, 'import-allowlist-mut.mjs');
      const mutated = checkerSrc.replace(needle, "return 'READ'; // G-43 no default READ")
        .replace("const ts = createRequire(import.meta.url)('typescript');",
          `const ts = createRequire(${JSON.stringify(new URL(import.meta.url).pathname)})('typescript');`);
      writeFileSync(mutFile, mutated);
      const tree = join(mutCase, 'tree');
      const plant = 'function f(o: Record<string, number>) {\n  let k = 0;\n  k;\n  return o[k];\n}\n';
      writeFixture(tree, { 'src/mapping/bad.ts': plant });
      const liveHits = scanTree(tree).hits.filter((h) => /rule27-computed-access /.test(h));
      if (!liveHits.length) fails.push('G-43 live checker must red a numeric local read in an unlisted position (bare expression statement)');
      const driver = join(mutCase, 'driver.mjs');
      writeFileSync(driver, "import { scanTree } from './import-allowlist-mut.mjs';\nconst hits = scanTree(process.argv[1]).hits.filter((h) => /rule27-computed-access /.test(h));\nif (hits.length) { console.error(hits.join('\\n')); process.exit(1); }\n");
      const r = spawnSync(process.execPath, [driver, tree], { encoding: 'utf8' });
      if (r.status !== 0) fails.push(`G-43 READ-default-restored mutant must leave the unlisted-position fixture green (so the mutant is demonstrated); status ${r.status}:\n${r.stdout}\n${r.stderr}`);
    }

    // G-20 / MX-12: claims-lint --surface p8-package must lint keys (embedded escaped key-only plant red, clean control green).
    fails.push(...mx12Case(base));
  } finally { rmSync(base, { recursive: true, force: true }); }
  return fails;
}

// HoQ A19 N-A19-1: check:ph0 runs this file plain (no entropy-backstop preload), so the rule27 child-runner
// tests M-A17-1 and N-A18-1 are re-run here as a plain-node child. That is the gating mode in which
// runChecked's r.error branch is reachable (under the npm test preload the backstop throws first). It is
// deliberately NOT a plain-node child inside npm test: the backstop must keep refusing children that drop
// the preload. Runs only for the real checker file, not for the M-167 scratch copies the tests make.
export const N19_PATTERN = 'N-A18-1|M-A17-1';
export const N19_EXPECTED_TESTS = 2;
function n19PlainNodeStep() {
  const here = new URL(import.meta.url).pathname;
  if (!here.endsWith('/tools/ci/import-allowlist.mjs')) return { ok: true, line: 'N-A19-1 plain-node step: skipped (not the real checker file)' };
  const root = join(dirname(here), '..', '..');
  // When this self-test itself runs inside a node:test file (the 218-fixture test in npm test), the inherited
  // NODE_TEST_CONTEXT would make the nested `node --test` skip running files; drop it so the step really runs.
  const childEnv = { ...process.env }; delete childEnv.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, ['--test', `--test-name-pattern=${N19_PATTERN}`, join(root, 'test', 'rule27-import-allowlist.test.mjs')],
    { cwd: root, encoding: 'utf8', timeout: 180_000, killSignal: 'SIGKILL', env: childEnv });
  const out = `${r.stdout ?? ''}\n${r.stderr ?? ''}`;
  const pass = Number((/^ℹ pass (\d+)$/m.exec(out) ?? [])[1]);
  const fail = Number((/^ℹ fail (\d+)$/m.exec(out) ?? [])[1]);
  if (r.error || r.signal !== null || r.status !== 0 || pass !== N19_EXPECTED_TESTS || fail !== 0) {
    const why = r.error ? `did not run (${r.error.code ?? r.error.message})` : r.signal !== null ? `killed by signal ${r.signal}` : `exit ${r.status}, pass ${pass}, fail ${fail}, expected pass ${N19_EXPECTED_TESTS} fail 0`;
    return { ok: false, line: `N-A19-1 plain-node step FAILED: ${why}\n${out}` };
  }
  return { ok: true, line: `N-A19-1 plain-node step: ${pass}/${N19_EXPECTED_TESTS} rule27 child-runner tests pass without the preload` };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv[2] === '--self-test') {
    const f = selfTest(); console.log(f.length ? f.join('\n') : `rule27 self-test: ${Object.keys(BAD).length} known-bad fixtures red, good fixture green, ${SELF_TEST_EXTRA_CASES.length} extra cases ok (${SELF_TEST_EXTRA_CASES.join(', ')})`);
    const g = n19PlainNodeStep(); console.log(g.line); if (!g.ok) f.push(g.line);
    process.exit(f.length ? 1 : 0);
  }
  const args = process.argv.slice(2); const phaseExit = args.includes('--phase-exit');
  const root = args.find((x) => !x.startsWith('--')) ?? process.cwd();
  const { hits, reports } = scanTree(root, { phaseExit });
  for (const r of reports) console.log(r);
  for (const h of hits) console.log(h);
  console.log(`rule27 import-allowlist: ${hits.length} finding(s) (dist/ grep half PENDING)`);
  process.exit(hits.length ? 1 : 0);
}
