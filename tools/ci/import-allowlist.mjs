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
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
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
const READ_CALL_NAME = /^(?:(?:fill|read)[\w$]*|randomBytes|randomFill[\w$]*|getRandomValues|randomUUID|randomInt)$/;

function walk(d, out = []) {
  let names; try { names = readdirSync(d); } catch { return out; }
  for (const n of names.sort()) { if (n === 'node_modules') continue; const p = join(d, n); const s = statSync(p); if (s.isDirectory()) walk(p, out); else if (EXT.test(n)) out.push(p); }
  return out;
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

export function scanFile(rel, src) {
  const hits = []; const pairs = [];
  const top = rel.startsWith('src/') ? (rel.split('/')[1] ?? '') : rel.split('/').slice(0, 2).join('/');
  const inVerify = rel.startsWith('src/verify/') || rel.startsWith('verify/');
  const add = (idx, code, msg) => hits.push(`${rel}:${lineOf(src, idx)}: rule27-${code} ${msg}`);
  const addNode = (node, code, msg) => add(node.getStart(), code, msg);
  const isCrypto = (s) => s === 'node:crypto' || s === 'crypto';

  const sf = parseSource(rel, src);
  for (const d of parseErrors(sf)) add(d.start ?? 0, 'parse', ts.flattenDiagnosticMessageText(d.messageText, '\n'));

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
  }

  const dps = [];
  visit(sf, (node) => {
    if ((ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) && hasUnicodeEscape(node)) {
      addNode(node, 'unicode-escape', `unicode escape in identifier '${node.getText()}' (decoded '${idText(node)}')`);
    }
    if (isLiteralPropertyKey(node) && hasUnicodeEscape(node)) {
      addNode(node, 'unicode-escape', `unicode escape in string-literal property key ${node.getText()}`);
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

export function scanTree(root, { phaseExit = false } = {}) {
  const hits = []; const pairs = []; const reports = [];
  for (const f of SCAN_ROOTS.flatMap((r) => walk(join(root, r)))) {
    const rel = relative(root, f).split(sep).join('/');
    const r = scanFile(rel, readFileSync(f, 'utf8'));
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
};
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
};
// Control planted the same way: the single allow-listed declaration stays green (report-only).
export const ALLOW_CONTROL = 'export const FINGERPRINT_BYTES = 16;\n';
// Where each known-bad fixture is planted (default src/mapping/bad.ts).
export const BAD_PATH = { 'audited-import': 'src/audited/bad.ts', 'createHash-outside-evidence': 'src/entropy/bad.ts',
  'capability-crypto': 'packages/capability/src/bad.ts', 'mapping-namespace': 'packages/mapping/src/bad.ts',
  'verify-drbg': 'src/verify/bad.ts', 'verify-drbg-relative': 'src/verify/bad.ts', 'verify-binding-wrong-path': 'src/verify/testingBinding.ts',
  'entropy-alias': 'src/entropy/bad.ts', 'entropy-other-path': 'src/entropy/bad.ts', 'randomFillSync-outside-entropy': 'src/mapping/bad.ts',
  ...Object.fromEntries(Object.keys(BAD).filter((n) => n.startsWith('allowlist-')).map((n) => [n, 'src/entropy/a.ts'])),
  'guard-forms-non-guard-path': 'packages/capability/src/other.ts' };
export const GUARD_OK = "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n";

export function writeFixture(dir, extra = {}) {
  for (const [p, s] of Object.entries({ ...GOOD, ...extra })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), s); }
}

export const SELF_TEST_EXTRA_CASES = ['allowlist-control', 'guard-control', 'MX-12 p8-package key plant', 'MX-12 clean control'];
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

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'rule27-'));
  try {
    const g = join(base, 'good'); writeFixture(g);
    const gr = scanTree(g).hits; if (gr.length) fails.push(`good fixture not green:\n${gr.join('\n')}`);
    for (const [name, src] of Object.entries(BAD)) {
      const d = join(base, name); const file = BAD_PATH[name] ?? 'src/mapping/bad.ts';
      writeFixture(d, { [file]: src });
      const hits = scanTree(d).hits;
      if (hits.length === 0) fails.push(`known-bad fixture ${name} did not turn rule 27 red`);
      else if (BAD_REASON[name] && !hits.some((h) => BAD_REASON[name].test(h))) fails.push(`known-bad fixture ${name} is red for the wrong reason:\n${hits.join('\n')}`);
    }
    const c = join(base, 'allowlist-control'); writeFixture(c, { 'src/entropy/a.ts': ALLOW_CONTROL });
    const cr = scanTree(c).hits; if (cr.length) fails.push(`allow-list control (export const FINGERPRINT_BYTES = 16) not green:\n${cr.join('\n')}`);
    // G-20 / M-152b: the exact guard at GUARD_PATH stays green.
    const gd = join(base, 'guard-control'); writeFixture(gd, { [GUARD_PATH]: GUARD_SRC() });
    const gh = scanTree(gd).hits; if (gh.length) fails.push(`guard-exact control not green:\n${gh.join('\n')}`);
    // G-20 / MX-12: claims-lint --surface p8-package must lint keys (embedded escaped key-only plant red, clean control green).
    fails.push(...mx12Case(base));
  } finally { rmSync(base, { recursive: true, force: true }); }
  return fails;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv[2] === '--self-test') {
    const f = selfTest(); console.log(f.length ? f.join('\n') : `rule27 self-test: ${Object.keys(BAD).length} known-bad fixtures red, good fixture green, ${SELF_TEST_EXTRA_CASES.length} extra cases ok (${SELF_TEST_EXTRA_CASES.join(', ')})`); process.exit(f.length ? 1 : 0);
  }
  const args = process.argv.slice(2); const phaseExit = args.includes('--phase-exit');
  const root = args.find((x) => !x.startsWith('--')) ?? process.cwd();
  const { hits, reports } = scanTree(root, { phaseExit });
  for (const r of reports) console.log(r);
  for (const h of hits) console.log(h);
  console.log(`rule27 import-allowlist: ${hits.length} finding(s) (dist/ grep half PENDING)`);
  process.exit(hits.length ? 1 : 0);
}
