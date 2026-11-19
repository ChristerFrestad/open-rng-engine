#!/usr/bin/env node
// Rule 22 — core exports allowlist (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L136 R-28, L537, L825 item (22); quality v5.5.7 L278 QR-33, L584 CI 15.
// The core package.json `exports` keys must be exactly {".", "./audited", "./package.json"}
// and each key is pinned to exactly one target (EXPORT_TARGET_PINS). Targets that are
// absolute, '../', or under node_modules are red. `imports`, `browser` and `typesVersions`
// are red; `main` is red unless it equals the pinned '.' target.
//
// Interim exported-name scan (Q1, until api-report.md exists at the first packed build):
// follow '.' and './audited' through every export target, `export *` and re-export.
// Red on any export originating in src/entropy, on any raw-bytes API, and on any QR-33
// term appearing as a camelCase/_ name segment of a core export. The labkit and
// docs/examples import edge is in this rule. A 'card' identifier in docs/examples
// stays green when the core does not import or re-export it.
//
// PENDING: the api-extractor api-report.md half starts at the first packed build (PH3).
// The `files` field and `npm audit signatures` in CI are backlog preconditions for that
// first packed build; they are not added to package.json while the current G4 holds.

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve, sep, isAbsolute, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import ts from 'typescript';

export const REQUIRED_EXPORT_KEYS = Object.freeze(['.', './audited', './package.json']);
export const EXPORT_TARGET_PINS = Object.freeze({
  '.': './src/index.ts',
  './audited': './src/audited/index.ts',
  './package.json': './package.json',
});
export const FORBIDDEN_EXPORT_SEGMENTS = Object.freeze([
  '-testing', '-edge-experimental', 'packages/drbg', 'packages/mapping', 'packages/capability',
]);
export const QR33_TERM_ESCAPES = Object.freeze([
  '\\u0064\\u0065\\u0063\\u006b',
  '\\u0063\\u0061\\u0072\\u0064',
  '\\u0073\\u0068\\u006f\\u0065',
  '\\u0072\\u0065\\u0065\\u006c',
  '\\u0073\\u0074\\u0072\\u0069\\u0070',
  '\\u0070\\u0061\\u0079\\u006c\\u0069\\u006e\\u0065',
  '\\u0070\\u0061\\u0079\\u0074\\u0061\\u0062\\u006c\\u0065',
  '\\u0072\\u0074\\u0070',
  '\\u0072\\u006f\\u0075\\u006c\\u0065\\u0074\\u0074\\u0065',
  '\\u0070\\u006f\\u0063\\u006b\\u0065\\u0074',
  '\\u0070\\u006f\\u006b\\u0065\\u0072',
  '\\u0068\\u006f\\u006c\\u0064\\u0065\\u006d',
  '\\u0068\\u0061\\u006e\\u0064',
  '\\u0062\\u0075\\u0072\\u006e',
]);
export const RAW_BYTES_APIS = Object.freeze([
  'randomFillSync', 'randomBytes', 'randomFill', 'getRandomValues', 'randomUUID', 'randomInt',
]);
export const PUBLIC_ENTRY_KEYS = Object.freeze(['.', './audited']);

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
export const QR33_TERMS = Object.freeze(QR33_TERM_ESCAPES.map(uUnescape));

function collectStrings(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => collectStrings(x, out));
  return out;
}

function pathReachesForbidden(p) {
  const n = String(p).split('\\').join('/');
  if (n.includes('*')) return false; // wildcard keys are a separate hit
  for (const seg of FORBIDDEN_EXPORT_SEGMENTS) {
    if (seg.startsWith('-')) {
      // package-name fragment: match as a path segment containing the suffix/name
      const parts = n.split('/');
      if (parts.some((part) => part.includes(seg))) return seg;
    } else if (n.includes(seg)) return seg;
  }
  return null;
}


function posix(p) { return String(p).split(sep).join('/'); }

export function nameSegments(id) {
  return String(id)
    .split(/_+/g)
    .flatMap((part) => part.split(/[0-9]+/))
    .flatMap((part) => part.split(/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/))
    .map((s) => s.toLowerCase())
    .filter(Boolean);
}

function segmentMatchesTerm(seg, term) {
  const s = String(seg).toLowerCase();
  const t = String(term).toLowerCase();
  return s === t || s === t + 's' || s === t + 'es';
}

// G-42 (HoQ a43a432c): Cyrillic/Greek look-alikes fold to Latin before matching; any other non-ASCII
// character in an export or member name is red on its own (exportNameNonAscii).
const QR33_CONFUSABLES = Object.freeze({
  '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0445': 'x', '\u0443': 'y',
  '\u043a': 'k', '\u043c': 'm', '\u0442': 't', '\u043d': 'h', '\u0432': 'b', '\u0455': 's', '\u0456': 'i',
  '\u0458': 'j', '\u0501': 'd', '\u04bb': 'h', '\u04cf': 'l', '\u0410': 'A', '\u0421': 'C', '\u0415': 'E',
  '\u041e': 'O', '\u0420': 'P', '\u0425': 'X', '\u041a': 'K', '\u041c': 'M', '\u0422': 'T', '\u041d': 'H',
  '\u0412': 'B', '\u0405': 'S', '\u0406': 'I', '\u0408': 'J', '\u03bf': 'o', '\u03b1': 'a', '\u03c1': 'p',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039a': 'K', '\u039c': 'M',
  '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X', '\u03a5': 'Y', '\u0396': 'Z',
});
export function foldConfusables(name) {
  return [...String(name).normalize('NFKC')].map((c) => QR33_CONFUSABLES[c] ?? c).join('');
}
export function exportNameNonAscii(name) {
  return /[^\x00-\x7f]/.test(String(name));
}

// QR-33 segmentation (HoQ ruling, CTO relay 2026-11-18 23:30 CET): a term matches a WHOLE camel or snake
// segment or its plural, or is a substring inside ONE segment (the substring scan stays). It is never
// stitched across a segment boundary ('_', digits, or a camel break), so names whose letters only join
// into a term across segments are green.
//
// G-42 regression (HoQ b15a2ff5 gap 1, CTO batch E): a run of two or more WHOLE consecutive segments whose
// concatenation equals a term or its plural is also red (term 11 split as snake, upper snake or camel). That is a sequence of
// whole segments, not a substring of the joined name: start_page (start+page) never equals a term.
export function segmentRunMatchesTerm(segs, t) {
  for (let i = 0; i < segs.length; i++) {
    let run = segs[i];
    for (let j = i + 1; j < segs.length && run.length < t.length + 2; j++) {
      run += segs[j];
      if (segmentMatchesTerm(run, t)) return true;
    }
  }
  return false;
}
export function qr33Hit(name) {
  const segs = nameSegments(foldConfusables(name));
  for (const t of QR33_TERMS) {
    if (segs.some((s) => segmentMatchesTerm(s, t))) return t;
    if (segs.some((s) => s.includes(t))) return t; // substring scan, within one segment only
    if (segmentRunMatchesTerm(segs, t)) return t; // whole consecutive segments, never the joined name
  }
  return null;
}

// QR-33 segmentation controls (HoQ ruling): names whose letters join into a term only across a segment
// boundary are green; a whole segment or a substring inside one segment stays red. Red names are built
// from the escaped term list, never written literally.
export const QR33_BOUNDARY_GREEN = Object.freeze(['start_page', 'short_poll', 'import_path', 'sort_product', 'part_power', 'cash_and', 'sub_urn', 'startProcess']);
export function qr33BoundaryRed() {
  const t0 = uUnescape(QR33_TERM_ESCAPES[0]);
  const t12 = uUnescape(QR33_TERM_ESCAPES[12]);
  return [`check${t0[0].toUpperCase()}${t0.slice(1)}`, `${t0}${t12}`];
}

const G42_GRAPH_BASE = 9;
const QR33_SEG_RED_CASES = 2;
// G-42 residual cases; term text is built from the escaped term list, never written literally.
export function g42Cases(cardName) {
  const Card = cardName[0].toUpperCase() + cardName.slice(1);
  const deal = `deal${Card}`;
  const aud = { 'src/audited/index.ts': 'export {};\n' };
  const homoglyph = [...cardName].map((c) => ({ a: '\u0430', c: '\u0441' }[c] ?? c)).join('');
  return [
    { name: 'g42-static-string', files: { 'src/index.ts': `export class C { static '${deal}' = 1; }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-static-computed', files: { 'src/index.ts': `export class C { static ['${deal}'] = 1; }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-static-private', files: { 'src/index.ts': `export class C { static #${deal} = 1; }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-enum-member', files: { 'src/index.ts': `export enum Suit { ${Card} }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-interface-member', files: { 'src/index.ts': `export interface I { ${deal}: number }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-instance-method', files: { 'src/index.ts': `export class C { ${deal}() { return 1; } }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-homoglyph', files: { 'src/index.ts': `export const ${homoglyph} = 1;\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-non-ascii', files: { 'src/index.ts': 'export const caf\u00e9 = 1;\n', ...aud }, reason: /non-ASCII character/ },
    // G-42 carry-over (HoQ 4c7adda0/f575fe1f §3.3; b15a2ff5 gap 2).
    { name: 'g42-ctor-param-public', files: { 'src/index.ts': `export class C { constructor(public ${deal}: number) {} }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-ctor-param-readonly', files: { 'src/index.ts': `export class C { constructor(private readonly ${deal}: number) {} }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-type-literal-member', files: { 'src/index.ts': `export type T = { ${deal}: number };\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-type-literal-nested', files: { 'src/index.ts': `export type T = { a: { b: Array<{ ${deal}(): void }> } };\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-interface-nested-literal', files: { 'src/index.ts': `export interface I { a: { ${deal}: number } }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-function-param-literal', files: { 'src/index.ts': `export function f(o: { ${deal}: number }) { return o; }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-namespace-member', files: { 'src/index.ts': `export namespace N { export const ${deal} = 1; }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-namespace-nested', files: { 'src/index.ts': `export namespace A.B { export function ${deal}() { return 1; } }\n`, ...aud }, reason: /QR-33 term/ },
    { name: 'g42-namespace-class-member', files: { 'src/index.ts': `export namespace N { export class K { static ${deal} = 1; } }\n`, ...aud }, reason: /QR-33 term/ },
  ];
}

// G-42 regression (HoQ b15a2ff5 gap 1): whole-segment runs equal to a term (index 11) are red, in every
// case form and plural; built from the escaped term list. Also a whole-segment control built from term 1.
export function qr33RunRed() {
  const t11 = uUnescape(QR33_TERM_ESCAPES[11]);
  const a = t11.slice(0, 4), b = t11.slice(4);
  const t1 = uUnescape(QR33_TERM_ESCAPES[1]);
  const t6 = uUnescape(QR33_TERM_ESCAPES[6]);
  return [`${a}_${b}`, `${a.toUpperCase()}_${b.toUpperCase()}`, `${a}${b[0].toUpperCase()}${b.slice(1)}`, `${a}_${b}s`, `${t6.slice(0, 3)}_${t6.slice(3, 5)}_${t6.slice(5)}`, `deal_${t1}`];
}
// Run-check green controls: whole-segment runs that do not equal a term, and boundary names.
export function qr33RunGreen() {
  const t11 = uUnescape(QR33_TERM_ESCAPES[11]);
  return [`${t11.slice(0, 4)}_${t11.slice(4)}u`, `${t11.slice(0, 3)}_x_${t11.slice(3)}`, 'deal_cart'];
}

export const QR33_ALLOW_REL = 'tools/qr33-allow.json';
export const QR33_ALLOW_SHA256 = 'db2d0ab03ee56d327244ee982b0712dae4acc22f251927ed5437863f641b35ba';

export function loadQr33Allow(abs) {
  const data = JSON.parse(readFileSync(abs, 'utf8'));
  if (!data || !Array.isArray(data.entries)) {
    throw new Error(`qr33-allow: ${abs} must be { schema, entries: [...] }`);
  }
  for (const e of data.entries) {
    if (!e || typeof e.entry !== 'string' || typeof e.hoqRulingRef !== 'string' || typeof e.fixture !== 'string') {
      throw new Error(`qr33-allow: entry must be {entry, hoqRulingRef, fixture}`);
    }
  }
  return data.entries;
}

function allowSet(entries) {
  return new Set((entries ?? []).map((e) => e.entry));
}

function isPinnedScalar(val) {
  return typeof val === 'string';
}

export function targetIsBannedShape(t) {
  if (typeof t !== 'string' || t.length === 0) return 'empty or non-string';
  const n = t.split('\\').join('/');
  if (isAbsolute(n) || /^[A-Za-z]:\//.test(n) || n.startsWith('/')) return 'absolute';
  if (n === '..' || n.startsWith('../') || n.includes('/../')) return "'../'";
  if (n.split('/').includes('node_modules')) return 'node_modules';
  return null;
}

function resolveRel(fromRel, spec) {
  const base = posix(fromRel).split('/').slice(0, -1).join('/');
  return posix(join(base || '.', spec)).replace(/^\.\//, '');
}

function isLabkitOrExamplesSpec(fromRel, spec) {
  const n = posix(spec);
  if (n === 'labkit' || n.startsWith('labkit/') || n.split('/').includes('labkit')) return 'labkit';
  if (n.includes('docs/examples') || n.startsWith('docs/examples')) return 'docs/examples';
  if (n.startsWith('.')) {
    const dest = resolveRel(fromRel, n);
    if (dest === 'docs/examples' || dest.startsWith('docs/examples/')) return 'docs/examples';
    if (dest === 'labkit' || dest.startsWith('labkit/') || dest.split('/').includes('labkit')) return 'labkit';
  }
  return null;
}

function isSourceFile(rel) {
  return /\.(ts|mts|cts|js|mjs|cjs)$/.test(rel);
}

// G-42 carry-over (HoQ 4c7adda0/f575fe1f §3.3, b15a2ff5 gap 2): names of members declared inside type
// literals anywhere under a node (type aliases, interface member types, nested literals).
function typeLiteralMemberNames(node) {
  const out = [];
  const visit = (n) => {
    if (ts.isTypeLiteralNode(n)) for (const m of n.members) { const x = memberNameText(m.name); if (x !== null) out.push(x); }
    ts.forEachChild(n, visit);
  };
  if (node) visit(node);
  return out;
}

// Constructor parameter properties (`constructor(public x)`, private, protected, readonly, override).
const PARAM_PROPERTY_KINDS = new Set([ts.SyntaxKind.PublicKeyword, ts.SyntaxKind.PrivateKeyword, ts.SyntaxKind.ProtectedKeyword, ts.SyntaxKind.ReadonlyKeyword, ts.SyntaxKind.OverrideKeyword]);
function constructorParameterProperties(cls) {
  const out = [];
  for (const m of cls.members) {
    if (!ts.isConstructorDeclaration(m)) continue;
    for (const p of m.parameters) {
      if ((p.modifiers ?? []).some((x) => PARAM_PROPERTY_KINDS.has(x.kind))) out.push(...bindingNames(p.name));
    }
  }
  return out;
}

function exportedBindings(sf) {
  return exportedBindingsOf(sf.statements);
}

function exportedBindingsOf(statements) {
  const out = [];
  for (const st of statements) {
    if (ts.isExportDeclaration(st)) {
      const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) ? st.moduleSpecifier.text : null;
      if (st.exportClause && ts.isNamedExports(st.exportClause)) {
        for (const el of st.exportClause.elements) {
          out.push({ name: el.name.text, local: (el.propertyName ?? el.name).text, from: spec, star: false, typ: !!st.isTypeOnly });
        }
      } else if (st.exportClause && ts.isNamespaceExport(st.exportClause)) {
        out.push({ name: st.exportClause.name.text, local: st.exportClause.name.text, from: spec, star: false, ns: true });
      } else if (!st.exportClause && spec) {
        out.push({ name: '*', local: '*', from: spec, star: true });
      }
    }
    if (ts.isExportAssignment(st) && !st.isExportEquals) out.push({ name: 'default', local: 'default', from: null, star: false });
    const mods = st.modifiers ?? [];
    const exported = mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st) || ts.isInterfaceDeclaration(st) || ts.isTypeAliasDeclaration(st) || ts.isEnumDeclaration(st)) {
      if (st.name) out.push({ name: st.name.text, local: st.name.text, from: null, star: false });
    }
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        for (const name of bindingNames(d.name)) out.push({ name, local: name, from: null, star: false });
      }
    }
    const member = (name) => out.push({ name, local: name, from: null, star: false, member: true });
    if (ts.isClassDeclaration(st)) {
      for (const name of classStaticNames(st)) out.push({ name, local: name, from: null, star: false, staticMember: true });
      // G-42: instance members, string/computed-literal and #private names count too.
      for (const name of classMemberNames(st, false)) member(name);
      for (const name of constructorParameterProperties(st)) member(name);
      for (const name of typeLiteralMemberNames(st)) member(name);
    }
    if (ts.isEnumDeclaration(st)) {
      for (const m of st.members) { const n = memberNameText(m.name); if (n !== null) member(n); }
    }
    if (ts.isInterfaceDeclaration(st)) {
      for (const m of st.members) { const n = memberNameText(m.name); if (n !== null) member(n); }
      for (const name of typeLiteralMemberNames(st)) member(name);
    }
    if (ts.isTypeAliasDeclaration(st)) for (const name of typeLiteralMemberNames(st.type)) member(name);
    if (ts.isFunctionDeclaration(st)) for (const name of typeLiteralMemberNames(st)) member(name);
    if (ts.isVariableStatement(st)) for (const name of typeLiteralMemberNames(st)) member(name);
    // Exported namespaces: the namespace name, and every exported member inside it (nested too).
    if (ts.isModuleDeclaration(st) && st.name && ts.isIdentifier(st.name)) {
      out.push({ name: st.name.text, local: st.name.text, from: null, star: false });
      let body = st.body;
      while (body && ts.isModuleDeclaration(body)) { out.push({ name: body.name.text, local: body.name.text, from: null, star: false, member: true }); body = body.body; }
      if (body && ts.isModuleBlock(body)) for (const b of exportedBindingsOf(body.statements)) if (!b.star && b.from === null) out.push({ ...b, member: true });
    }
  }
  return out;
}

function bindingNames(name) {
  if (!name) return [];
  if (ts.isIdentifier(name)) return [name.text];
  const out = [];
  const walk = (n) => {
    if (!n) return;
    if (ts.isIdentifier(n)) { out.push(n.text); return; }
    if (ts.isObjectBindingPattern(n) || ts.isArrayBindingPattern(n)) {
      for (const el of n.elements) {
        if (ts.isOmittedExpression(el)) continue;
        if (ts.isBindingElement(el)) walk(el.name);
        else walk(el);
      }
    }
  };
  walk(name);
  return out;
}

function memberNameText(n) {
  if (!n) return null;
  if (ts.isIdentifier(n) || ts.isPrivateIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text.replace(/^#/, '');
  if (ts.isComputedPropertyName(n)) {
    const e = n.expression;
    if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e) || ts.isNumericLiteral(e)) return e.text;
  }
  return null;
}

function classStaticNames(cls) {
  return classMemberNames(cls, true);
}

function classMemberNames(cls, isStatic) {
  const out = [];
  for (const m of cls.members) {
    const mods = m.modifiers ?? [];
    if (mods.some((x) => x.kind === ts.SyntaxKind.StaticKeyword) !== isStatic) continue;
    const n = memberNameText(m.name);
    if (n !== null) out.push(n);
  }
  return out;
}

function specifiersOf(sf) {
  const out = [];
  const take = (spec) => { if (spec && ts.isStringLiteral(spec)) out.push(spec.text); };
  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) take(node.moduleSpecifier);
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) take(node.arguments[0]);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') take(node.arguments[0]);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

export function walkPublicExports(root, entries, { qr33Allow = [] } = {}) {
  const hits = [];
  const allowed = allowSet(qr33Allow);
  const seen = new Set();
  const todo = entries.map((rel) => ({ rel: posix(rel), fromPublic: true }));
  const emit = (rel, name, originRel) => {
    if (RAW_BYTES_APIS.includes(name)) hits.push(`${rel}:1: rule22-exports raw-bytes API '${name}' is in the public core API`);
    if (exportNameNonAscii(name)) hits.push(`${rel}:1: rule22-exports core export '${name}' has a non-ASCII character (G-42)`);
    const q = qr33Hit(name);
    if (q && !allowed.has(name)) hits.push(`${rel}:1: rule22-exports core export '${name}' contains QR-33 term '${q}'`);
    if (originRel && posix(originRel).startsWith('src/entropy/')) {
      hits.push(`${rel}:1: rule22-exports public API re-exports '${name}' originating in ${originRel}`);
    }
  };
  const visitFile = (rel, followExports) => {
    const abs = join(root, rel);
    if (!existsSync(abs)) return;
    if (!isSourceFile(rel)) return;
    const src = readFileSync(abs, 'utf8');
    const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    for (const spec of specifiersOf(sf)) {
      const edge = isLabkitOrExamplesSpec(rel, spec);
      if (edge) hits.push(`${rel}:1: rule22-exports core import edge to ${edge} ('${spec}')`);
      if (typeof spec === 'string' && spec.startsWith('.')) {
        const dest = resolveRel(rel, spec);
        const key = `walk:${dest}`;
        if (!seen.has(key)) { seen.add(key); visitFile(dest, false); }
      }
    }
    if (!followExports) return;
    for (const b of exportedBindings(sf)) {
      if (b.star && b.from && b.from.startsWith('.')) {
        const dest = resolveRel(rel, b.from);
        const destAbs = join(root, dest);
        if (existsSync(destAbs) && isSourceFile(dest)) {
          const destSf = ts.createSourceFile(dest, readFileSync(destAbs, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
          for (const inner of exportedBindings(destSf)) {
            if (inner.star) {
              const key = `star:${dest}:${inner.from}`;
              if (!seen.has(key) && inner.from && inner.from.startsWith('.')) {
                seen.add(key);
                visitFile(resolveRel(dest, inner.from), true);
              }
            } else {
              emit(rel, inner.name, dest);
              if (inner.from && inner.from.startsWith('.')) visitFile(resolveRel(dest, inner.from), true);
            }
          }
        }
        continue;
      }
      if (b.from && b.from.startsWith('.')) {
        const dest = resolveRel(rel, b.from);
        emit(rel, b.name, dest);
        visitFile(dest, true);
      } else {
        emit(rel, b.name, rel);
      }
    }
  };
  for (const { rel } of todo) {
    const key = `entry:${rel}`;
    if (seen.has(key)) continue;
    seen.add(key);
    visitFile(rel, true);
  }
  return hits;
}

export function scanExports(pkg, { path = 'package.json' } = {}) {
  const hits = [];
  if (!pkg || typeof pkg !== 'object') {
    hits.push(`${path}:1: rule22-exports missing or unreadable package.json`);
    return hits;
  }
  if (pkg.exports === undefined) {
    hits.push(`${path}:1: rule22-exports 'exports' is missing; keys must be exactly {".", "./audited", "./package.json"}`);
    return hits;
  }
  const exp = pkg.exports;
  if (typeof exp !== 'object' || exp === null || Array.isArray(exp)) {
    hits.push(`${path}:1: rule22-exports 'exports' must be an object whose keys are exactly {".", "./audited", "./package.json"}`);
    return hits;
  }
  const keys = Object.keys(exp);
  const missing = REQUIRED_EXPORT_KEYS.filter((k) => !keys.includes(k));
  const extra = keys.filter((k) => !REQUIRED_EXPORT_KEYS.includes(k));
  if (missing.length || extra.length) {
    hits.push(`${path}:1: rule22-exports keys are {${keys.join(', ')}} but must be exactly {".", "./audited", "./package.json"}` +
      (missing.length ? ` (missing ${missing.join(', ')})` : '') +
      (extra.length ? ` (extra ${extra.join(', ')})` : ''));
  }
  for (const k of keys) {
    if (k.includes('*')) hits.push(`${path}:1: rule22-exports key '${k}' is a wildcard`);
    if (k === './drbg' || k.startsWith('./drbg/')) hits.push(`${path}:1: rule22-exports key '${k}' is ./drbg`);
    const val = exp[k];
    const pin = EXPORT_TARGET_PINS[k];
    if (pin !== undefined) {
      if (!isPinnedScalar(val) || val !== pin) {
        hits.push(`${path}:1: rule22-exports key '${k}' must be pinned to exactly '${pin}' (got ${JSON.stringify(val)})`);
      }
    }
    for (const t of collectStrings(val)) {
      if (typeof t === 'string' && t.includes('*')) hits.push(`${path}:1: rule22-exports target '${t}' of key '${k}' is a wildcard`);
      const bad = pathReachesForbidden(t);
      if (bad) hits.push(`${path}:1: rule22-exports key '${k}' reaches ${bad} (${t})`);
      const shape = targetIsBannedShape(t);
      if (shape) hits.push(`${path}:1: rule22-exports key '${k}' target '${t}' is ${shape}`);
    }
  }
  for (const field of ['imports', 'browser', 'typesVersions']) {
    if (pkg[field] !== undefined) hits.push(`${path}:1: rule22-exports '${field}' is red`);
  }
  if (pkg.main !== undefined && pkg.main !== EXPORT_TARGET_PINS['.']) {
    hits.push(`${path}:1: rule22-exports 'main' must be absent or exactly the pinned '.' target '${EXPORT_TARGET_PINS['.']}'; found ${JSON.stringify(pkg.main)}`);
  }
  return hits;
}

export function publicEntryRels(pkg) {
  const exp = pkg && pkg.exports;
  const rels = [];
  if (exp && typeof exp === 'object' && !Array.isArray(exp)) {
    for (const key of PUBLIC_ENTRY_KEYS) {
      const val = exp[key];
      const pin = EXPORT_TARGET_PINS[key];
      const t = (typeof val === 'string' ? val : pin) ?? pin;
      if (typeof t === 'string' && t.startsWith('.')) rels.push(posix(t.replace(/^\.\//, '')));
    }
  }
  return [...new Set(rels)];
}

export function scanRoot(root, opts = {}) {
  const file = join(root, 'package.json');
  if (!existsSync(file)) return [`package.json:1: rule22-exports missing package.json`];
  let pkg;
  try { pkg = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { return [`package.json:1: rule22-exports unreadable package.json (${e.message})`]; }
  const hits = scanExports(pkg, { path: 'package.json' });
  let qr33Allow = opts.qr33Allow;
  if (qr33Allow === undefined) {
    const allowPath = join(root, QR33_ALLOW_REL);
    qr33Allow = existsSync(allowPath) ? loadQr33Allow(allowPath) : [];
    // G-42: the allow-list file is pinned; any edit is red in check:ph0, not only in npm test.
    if (existsSync(allowPath)) {
      const asha = createHash('sha256').update(readFileSync(allowPath)).digest('hex');
      if (asha !== QR33_ALLOW_SHA256) hits.push(`${QR33_ALLOW_REL}:1: rule22-exports qr33-allow.json sha256 ${asha} does not match the pinned ${QR33_ALLOW_SHA256}`);
    }
  }
  hits.push(...walkPublicExports(root, publicEntryRels(pkg), { qr33Allow }));
  return hits;
}

// Known-bad fixtures stored \u-escaped (CTO addendum 07:45), materialised only in scratch.
const GOOD_PKG = {
  name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module',
  exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' },
  dependencies: {},
};
export const BAD_FIXTURES = {
  'missing-exports': { pkg: { name: 'x', version: '0.0.0', private: true, type: 'module', dependencies: {} }, reason: /rule22-exports 'exports' is missing/ },
  'extra-drbg-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './drbg': './packages/drbg/src/index.ts' } }, reason: /rule22-exports/ },
  'wildcard-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './*': './src/*' } }, reason: /wildcard/ },
  'mapping-target': { pkg: { ...GOOD_PKG, exports: { '.': './packages/mapping/src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /packages\/mapping/ },
  'plain-extra-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './internal': './src/health/index.ts' } }, reason: /extra \.\/internal/ },
  'absolute-target': { pkg: { ...GOOD_PKG, exports: { '.': '/tmp/evil.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is absolute/ },
  'dotdot-target': { pkg: { ...GOOD_PKG, exports: { '.': '../evil.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is '\.\.\/'/ },
  'node-modules-target': { pkg: { ...GOOD_PKG, exports: { '.': './node_modules/typescript/lib/typescript.js', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is node_modules/ },
  'imports-field': { pkg: { ...GOOD_PKG, imports: { '#x': './src/index.ts' } }, reason: /'imports' is red/ },
  'browser-field': { pkg: { ...GOOD_PKG, browser: './src/index.ts' }, reason: /'browser' is red/ },
  'typesVersions-field': { pkg: { ...GOOD_PKG, typesVersions: { '*': { '*': ['./src/index.ts'] } } }, reason: /'typesVersions' is red/ },
  'main-not-pinned': { pkg: { ...GOOD_PKG, main: './src/verify/index.ts' }, reason: /'main' must be absent or exactly the pinned/ },
  'wrong-pin-package-json': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './src/verify/index.ts' } }, reason: /key '\.\/package\.json' must be pinned to exactly '\.\/package\.json'/ },
};

function writeJson(dir, rel, obj) {
  const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'r22-'));
  try {
    const ctl = join(base, 'control');
    writeJson(ctl, 'package.json', GOOD_PKG);
    mkdirSync(join(ctl, 'src/audited'), { recursive: true });
    writeFileSync(join(ctl, 'src/index.ts'), 'export {};\n');
    writeFileSync(join(ctl, 'src/audited/index.ts'), 'export {};\n');
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    // 'card' in docs/examples stays green when the core does not import or re-export it.
    const cardName = uUnescape(QR33_TERM_ESCAPES[1]);
    const examples = join(ctl, 'docs/examples');
    mkdirSync(examples, { recursive: true });
    writeFileSync(join(examples, 'demo.ts'), `export const ${cardName} = 1;\n`);
    const exHits = scanRoot(ctl);
    if (exHits.length) fails.push(`docs/examples ${cardName} control not green:\n${exHits.join('\n')}`);
    const graphCases = [
      {
        name: 'export-star-entropy',
        files: { 'src/index.ts': "export * from './entropy/index.ts';\n", 'src/entropy/index.ts': 'export const randomFillSync = 1;\n', 'src/audited/index.ts': 'export {};\n' },
        reason: /originating in src\/entropy\//,
      },
      {
        name: 'qr33-export-name',
        files: { 'src/index.ts': `export const ${cardName} = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'labkit-import-edge',
        files: { 'src/index.ts': "import x from 'labkit';\nexport const n = 1;\n", 'src/audited/index.ts': 'export {};\n' },
        reason: /import edge to labkit/,
      },
      {
        name: 'docs-examples-import-edge',
        files: { 'src/index.ts': "import x from '../docs/examples/demo.ts';\nexport const n = 1;\n", 'src/audited/index.ts': 'export {};\n' },
        reason: /import edge to docs\/examples/,
      },
      {
        name: 'raw-bytes-api-name',
        files: { 'src/index.ts': 'export const randomBytes = 1;\n', 'src/audited/index.ts': 'export {};\n' },
        reason: /raw-bytes API 'randomBytes'/,
      },
      {
        name: 'qr33-deal-plural',
        files: { 'src/index.ts': `export const deal${cardName[0].toUpperCase()}${cardName.slice(1)}s = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-substring',
        files: { 'src/index.ts': `export const ${cardName}${uUnescape(QR33_TERM_ESCAPES[0])} = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-destructured-export',
        files: { 'src/index.ts': `const o = { deal${cardName[0].toUpperCase()}${cardName.slice(1)}s: 1 };\nexport const { deal${cardName[0].toUpperCase()}${cardName.slice(1)}s } = o;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-class-static',
        files: { 'src/index.ts': `export class C { static ${cardName}${uUnescape(QR33_TERM_ESCAPES[0])} = 1; }\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      // G-42 residual (HoQ a43a432c, section 4).
      ...g42Cases(cardName),
      // QR-33 segmentation (HoQ ruling): a whole segment and a substring inside one segment stay red.
      ...qr33BoundaryRed().map((n, i) => ({ name: `qr33-seg-red-${i}`, files: { 'src/index.ts': `export const ${n} = 1;\n`, 'src/audited/index.ts': 'export {};\n' }, reason: /QR-33 term/ })),
      ...qr33RunRed().map((n, i) => ({ name: `qr33-run-red-${i}`, files: { 'src/index.ts': `export const ${n} = 1;\n`, 'src/audited/index.ts': 'export {};\n' }, reason: /QR-33 term/ })),
    ];
    // QR-33 segmentation green controls: a term stitched across a segment boundary is not a hit. The
    // former G-42 split-term case (term index 11 split by '_') is one of these under the ruling.
    // G-42 regression (HoQ b15a2ff5): the former split-term control is red again (qr33RunRed); the
    // run-check controls below stay green.
    for (const n of [...QR33_BOUNDARY_GREEN, ...qr33RunGreen()]) {
      const d = join(base, `qr33-seg-green-${n.replace(/[^A-Za-z0-9]/g, '-')}`);
      writeJson(d, 'package.json', GOOD_PKG);
      mkdirSync(join(d, 'src/audited'), { recursive: true });
      writeFileSync(join(d, 'src/index.ts'), `export const ${n} = 1;\n`);
      writeFileSync(join(d, 'src/audited/index.ts'), 'export {};\n');
      const hits = scanRoot(d);
      if (hits.length) fails.push(`qr33-seg-green ${n}: a term across a segment boundary must be green:\n${hits.join('\n')}`);
    }
    for (const [name, { pkg, reason }] of Object.entries(BAD_FIXTURES)) {
      // Materialise from a \u-escaped form; the escaped source is what we keep in-repo as the fixture text.
      const escaped = uEscape(JSON.stringify(pkg));
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(escaped)));
      const hits = scanRoot(d);
      if (!hits.some((h) => reason.test(h))) fails.push(`${name} did not turn rule 22 red:\n${hits.join('\n')}`);
    }
    for (const c of graphCases) {
      const d = join(base, c.name);
      writeJson(d, 'package.json', GOOD_PKG);
      for (const [rel, src] of Object.entries(c.files)) {
        const fp = join(d, rel); mkdirSync(dirname(fp), { recursive: true }); writeFileSync(fp, src);
      }
      const hits = scanRoot(d);
      if (!hits.some((h) => c.reason.test(h))) fails.push(`${c.name} did not turn rule 22 red:\n${hits.join('\n')}`);
    }
    // G-42: an edited allow-list file in the tree is red through scanRoot (sha compare), not only in npm test.
    const pinCase = join(base, 'qr33-allow-pin');
    writeJson(pinCase, 'package.json', GOOD_PKG);
    mkdirSync(join(pinCase, 'src/audited'), { recursive: true });
    writeFileSync(join(pinCase, 'src/index.ts'), 'export const n = 1;\n');
    writeFileSync(join(pinCase, 'src/audited/index.ts'), 'export {};\n');
    writeJson(pinCase, QR33_ALLOW_REL, { schema: 'qr33-allow/v1', entries: [{ entry: 'n', hoqRulingRef: 'scratch', fixture: 'qr33-allow-pin' }] });
    const pinHits = scanRoot(pinCase);
    if (!pinHits.some((h) => /qr33-allow\.json sha256 .* does not match the pinned/.test(h))) fails.push(`qr33-allow-pin: edited allow-list must be red:\n${pinHits.join('\n')}`);
    // Allow-list mechanism uses a scratch config, never the production file.
    const deal = `deal${cardName[0].toUpperCase()}${cardName.slice(1)}s`;
    const scratch = join(base, 'qr33-allow-scratch');
    writeJson(scratch, 'package.json', GOOD_PKG);
    mkdirSync(join(scratch, 'src/audited'), { recursive: true });
    writeFileSync(join(scratch, 'src/index.ts'), `export const ${deal} = 1;\n`);
    writeFileSync(join(scratch, 'src/audited/index.ts'), 'export {};\n');
    const redHits = scanRoot(scratch, { qr33Allow: [] });
    if (!redHits.some((h) => /QR-33 term/.test(h))) fails.push(`scratch allow: empty list must leave ${deal} red:\n${redHits.join('\n')}`);
    const greenHits = scanRoot(scratch, { qr33Allow: [{ entry: deal, hoqRulingRef: 'scratch', fixture: 'qr33-allow-scratch' }] });
    if (greenHits.some((h) => /QR-33 term/.test(h))) fails.push(`scratch allow: listed entry must be green:\n${greenHits.join('\n')}`);
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`rule22 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`rule22 self-test: ${Object.keys(BAD_FIXTURES).length + G42_GRAPH_BASE + g42Cases('x').length + QR33_SEG_RED_CASES + qr33RunRed().length + 1} known-bad fixtures red, ${QR33_BOUNDARY_GREEN.length + qr33RunGreen().length + 1} controls green`);
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && here === process.argv[1]) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) selfTest();
  else {
    const root = args.find((a) => !a.startsWith('-')) ?? process.cwd();
    const hits = scanRoot(root);
    if (hits.length) { hits.forEach((h) => console.log(h)); console.log(`rule22 exports-map: ${hits.length} finding(s)`); process.exit(1); }
    console.log('rule22 exports-map: 0 finding(s)');
  }
}
