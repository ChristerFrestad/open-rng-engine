#!/usr/bin/env node
// PLAN rule 40 / quality CI rule 31 / X-13: protected-name scanner (product scanner; replaces o55-scan.py once integrated).
// Zero dependencies. Sources: R-79 (CPO-owned list, CPO-reviewed changes, references-section allowlist), R-81 (P1-P9,
// generic vocabulary never banned, self-scan by exact path), quality v5.5.2 §7.5 (normalisation, SEP, fail closed,
// M-60/M-61/M-71), C-9 format inputs/cto-c9-protected-names-format.md dadae96e (incl. v1.1 errata E-1..E-8).
//
// Usage: node tools/ci/rule40-protected-names.mjs              scan the STAGED (index) bytes of every tracked path
//        node tools/ci/rule40-protected-names.mjs --worktree   scan tracked paths from the working tree
//        node tools/ci/rule40-protected-names.mjs --self-test [--worktree]  materialise the escaped known-bad fixture in scratch; expect
//                                                              >= 1 hit per P-group and per product-only entry
// Exit: 0 clean, 1 hits / NAMED_GAME_REFERENCE, 2 config error (list parse, approval pin, fixture, config schema).
//
// Exactly two content exemptions, by exact repo-relative path string (no globs, prefixes or patterns):
//   tools/protected-names.txt            parsed as scanner config; must parse, and its sha256 must equal the CPO approval pin
//   tools/protected-names.known-bad.json escaped fixture; must decode and, materialised, hit every P-group
// Both paths are still scanned as path names. Every other tracked path, including siblings such as
// tools/protected-names.txt.bak, is scanned in full. LICENSE is NOT exempt here (it is scanned like any file).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';

export const LIST_PATH = 'tools/protected-names.txt';
export const FIXTURE_PATH = 'tools/protected-names.known-bad.json';
export const CONFIG_PATH = 'tools/protected-names.config.json';
export const EXEMPT_PATHS = Object.freeze([LIST_PATH, FIXTURE_PATH]);
export const FORMAT_HEADER = 'format: open-rng-engine/protected-names/v1';
export const FIXTURE_FORMAT = 'open-rng-engine/rule40-known-bad/v1';
export const CONFIG_FORMAT = 'open-rng-engine/rule40-config/v1';
// Closed binary allowlist of text-free images (RQ-FC-23). Empty: any non-UTF-8 tracked file is red.
export const BINARY_ALLOWLIST = Object.freeze([]);

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// ---------- normalisation (quality §7.5; same steps as the o55 reference) ----------
// NFKC, then split camelCase / PascalCase on ASCII boundaries, then case-fold. JS has no casefold(); toUpperCase()
// followed by toLowerCase() gives the full-folding results that matter here (e.g. sharp s -> ss, final sigma).
export function normScan(s) {
  let t = s.normalize('NFKC');
  t = t.replace(/(?<=[a-z])(?=[A-Z])/g, ' ').replace(/(?<=[A-Z])(?=[A-Z][a-z])/g, ' ');
  return t.toUpperCase().toLowerCase();
}
const nfkcFold = (s) => s.normalize('NFKC').toUpperCase().toLowerCase();
export const SEP = "[\\s_\\-.'\u2019\u02bc`\u00b4]*";
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const bounded = (body) => new RegExp(`(?<![a-z0-9])(?:${body})(?![a-z0-9])`, 'g');

// ---------- list parser (C-9 §1-§4 + v1.1 errata) ----------
const GROUPS = new Set(['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9']);
const KINDS = new Set(['phrase', 'phrase-plural', 'product-only', 'regex']); // E-1: four kinds
const PRODUCT_ONLY = new Set(['s\u006cot', 's\u006cots']); // E-3: bare singular and plural, each its own entry
const TOKEN = /^[a-z0-9]+$/;
// Generic vocabulary (R-81): never banned. Guard runs every entry against these in all R-81 positions.
export const GENERIC_WORDS = Object.freeze(['card', 'deck', 'hand', 'wheel', 'pocket', 'reel', 'symbol', 'strip', 'paytable', 'game']);
export const GENERIC_EXTRAS = Object.freeze(['card-deal-52', 'wheel-37', 'reel-5x3', 'GAME_ERROR']);
// Closed TECHNICAL_TERM forms (PLAN L222, quality L1407, §7.5 L1088); a list entry equal to one is a parse error.
const S = 's\u006cot';
export const TECHNICAL_TERM_FORMS = Object.freeze([
  `last-read ${S}`, `last-read ${S}s`, `last read ${S}`, `last read ${S}s`, `${S} per width`, `one ${S} per width`,
  `fingerprint ${S}`, `cht ${S}s`, `CHT ${S}s`, `previous-block ${S}`, `previous-block ${S}s`, `previous block ${S}`,
  `previous block ${S}s`, `health ${S}s`, `process-wide ${S}`, `process wide ${S}`, `private ${S}`, `private-${S}`, `scratch ${S}`,
]);
const hyphenSpace = (s) => nfkcFold(s).replace(/[\s_-]+/g, ' ').trim();

function hasCapturingGroup(p) {
  const s = p.split('<SEP>').join('X');
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') { i++; continue; }
    if (s[i] === '(' && !/^\?[:=!]/.test(s.slice(i + 1))) return true;
  }
  return false;
}

export function compileEntry(kind, pattern) {
  if (kind === 'product-only') return bounded(reEscape(pattern));
  if (kind === 'phrase' || kind === 'phrase-plural') {
    const toks = pattern.split(' ').map(reEscape);
    if (kind === 'phrase-plural') toks[toks.length - 1] += 's?';
    return bounded(toks.join(SEP));
  }
  if (kind === 'regex') {
    if (/\\[1-9]|\\k<|\(\?P=/.test(pattern)) throw new Error(`regex backreference not allowed: ${pattern}`);
    if (/\(\?[a-zA-Z-]+[:)]/.test(pattern)) throw new Error(`regex flags not allowed: ${pattern}`);
    if (/\(\?<[=!]/.test(pattern)) throw new Error(`regex lookbehind not allowed (lookahead only): ${pattern}`);
    if (/\(\?<[A-Za-z]/.test(pattern)) throw new Error(`regex named group not allowed: ${pattern}`);
    if (hasCapturingGroup(pattern)) throw new Error(`REGEX_CAPTURING_GROUP: ${pattern}`);
    try { new RegExp(pattern.split('<SEP>').join(SEP)); return bounded(pattern.split('<SEP>').join(SEP)); } catch (e) { throw new Error(`regex does not compile: ${pattern} (${e.message})`); }
  }
  throw new Error(`unknown kind: ${kind}`);
}

export function parseList(buf) {
  const errors = [];
  const meta = { version: null, sha256: sha256(buf), entries: [] };
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) errors.push('encoding: UTF-8 BOM present');
  if (buf.includes(0x0d)) errors.push('encoding: CR / CRLF line endings (LF only required)');
  if (buf.length === 0 || buf[buf.length - 1] !== 0x0a) errors.push('encoding: missing final newline');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { errors.push('encoding: not UTF-8'); return { errors, meta }; }
  if (text.normalize('NFC') !== text) errors.push('encoding: not NFC-normalised');
  let lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines = lines.slice(0, -1);
  if (lines.length < 2) { errors.push('header: file shorter than the two required header lines'); return { errors, meta }; }
  if (lines[0].replace(/^\ufeff/, '') !== FORMAT_HEADER) errors.push(`header: line 1 is not ${JSON.stringify(FORMAT_HEADER)}`);
  const mv = /^version: ([1-9][0-9]*)$/.exec(lines[1]);
  if (!mv) errors.push("header: line 2 must be 'version: <positive integer>'"); else meta.version = Number(mv[1]);
  const ids = new Set();
  const kp = new Set();
  for (let li = 2; li < lines.length; li++) {
    const line = lines[li];
    const L = `L${li + 1}`;
    if (line !== line.replace(/[ \t]+$/, '')) errors.push(`${L}: trailing whitespace`);
    if (line === '') continue;
    if (line.startsWith('#')) { if (line.includes('\t')) errors.push(`${L}: tab in a comment`); continue; }
    const f = line.split('\t');
    if (f.length !== 5) { errors.push(`${L}: wrong field count ${f.length} (expected 5)`); continue; }
    const [id, group, kind, pattern, source] = f;
    const empty = ['id', 'group', 'kind', 'pattern', 'source'].filter((_, i) => f[i] === '');
    if (empty.length) errors.push(`${L}: empty field(s): ${empty.join(', ')}`);
    if (!/^PN-\d{3}$/.test(id)) errors.push(`${L}: id ${JSON.stringify(id)} is not PN-NNN`);
    if (ids.has(id)) errors.push(`${L}: duplicate id ${id}`); else if (id) ids.add(id);
    if (!GROUPS.has(group)) errors.push(`${L}: unknown group ${JSON.stringify(group)}`);
    if (!KINDS.has(kind)) errors.push(`${L}: unknown kind ${JSON.stringify(kind)}`);
    if (kind === 'regex' && group !== 'P7') errors.push(`${L}: regex outside P7 (${id})`);
    if (kind === 'product-only' && (group !== 'P7' || !PRODUCT_ONLY.has(pattern))) errors.push(`${L}: product-only is only for the bare P7 singular/plural entries`);
    if ((kind === 'phrase' || kind === 'phrase-plural') && pattern !== '' && !pattern.split(' ').every((t) => TOKEN.test(t))) errors.push(`${L}: phrase tokens must be [a-z0-9]+ separated by single spaces`);
    if (pattern) {
      const cmp = kind === 'regex' ? pattern.split('<SEP>').join('') : pattern;
      if (cmp !== nfkcFold(cmp) || cmp !== cmp.toLowerCase()) errors.push(`${L}: pattern is not normalised (NFKC + casefold, lowercase)`);
      if (TECHNICAL_TERM_FORMS.some((t) => hyphenSpace(t) === hyphenSpace(pattern))) errors.push(`${L}: TECHNICAL_TERM list form is flagged`);
    }
    if (source && /\s/.test(source)) errors.push(`${L}: source tag contains whitespace`);
    const key = `${kind}\u0000${nfkcFold(pattern)}`;
    if (kind && pattern) { if (kp.has(key)) errors.push(`${L}: duplicate normalised (kind, pattern)`); else kp.add(key); }
    let rx = null;
    if (KINDS.has(kind) && pattern && !empty.length) { try { rx = compileEntry(kind, pattern); } catch (e) { errors.push(`${L}: ${e.message}`); } }
    meta.entries.push({ id, group, kind, pattern, source, line: li + 1, rx });
  }
  if (meta.entries.length === 0) errors.push('empty list (zero entries)');
  for (const g of genericGuardHits(meta.entries)) errors.push(`generic-vocabulary guard: ${g}`);
  return { errors, meta };
}

// R-81 generic-vocabulary positions: singular, plural, camelCase identifier, heading, package.json keyword (+ name,
// description, example path), plus card-deal-52 / wheel-37 / reel-5x3 / GAME_ERROR. Any entry hit is a parse error.
export function genericFixtureTree() {
  const files = new Map();
  const lines = [];
  const headings = [];
  for (const w of GENERIC_WORDS) {
    const cap = w[0].toUpperCase() + w.slice(1);
    lines.push(w, `${w}s`, `${w}Count`, `my${cap}Value`);
    headings.push(`# ${cap}`, `## ${cap}s`);
  }
  lines.push(...GENERIC_EXTRAS);
  files.set('test/x13-fixtures/generic-vocabulary/README.md', `${headings.join('\n')}\n\n${lines.join('\n')}\n`);
  files.set('test/x13-fixtures/generic-vocabulary/package.json', `${JSON.stringify({ name: 'generic-vocabulary-fixture', description: GENERIC_WORDS.join(' '), keywords: [...GENERIC_WORDS, ...GENERIC_WORDS.map((w) => `${w}s`)] }, null, 2)}\n`);
  for (const w of [...GENERIC_WORDS, 'card-deal-52', 'wheel-37', 'reel-5x3']) files.set(`docs/examples/${w}/README.md`, `# ${w}\n`);
  return files;
}
function genericGuardHits(entries) {
  const out = [];
  const tree = genericFixtureTree();
  for (const [path, text] of tree) {
    for (const h of scanText(path, text, entries)) out.push(`${h.id} hit generic fixture ${path}:${h.line} "${h.match}"`);
    for (const h of scanPath(path, entries)) out.push(`${h.id} hit generic fixture path ${path}`);
  }
  return out;
}

// ---------- scanning ----------
// Product positions (C-9 §3, §7.5): package.json name/description/keywords, markdown headings, example names
// (any path segment under docs/examples/). Strict reading: in a product position every bare singular/plural token
// is flagged, including inside a TECHNICAL_TERM form; outside product positions product-only entries never apply.
const isPackageJson = (p) => p === 'package.json' || p.endsWith('/package.json');
const isMarkdown = (p) => /\.md$/i.test(p);
function productSpans(path, text) {
  const spans = []; // [line, text]
  const lines = text.split('\n');
  if (isMarkdown(path)) lines.forEach((l, i) => { if (/^\s{0,3}#{1,6}(\s|$)/.test(l)) spans.push([i + 1, l]); });
  if (isPackageJson(path)) {
    let j;
    try { j = JSON.parse(text); } catch { return { spans, error: 'package.json does not parse (product positions unscannable)' }; }
    const vals = [];
    if (typeof j.name === 'string') vals.push(['name', j.name]);
    if (typeof j.description === 'string') vals.push(['description', j.description]);
    if (Array.isArray(j.keywords)) for (const k of j.keywords) vals.push(['keywords', String(k)]);
    for (const [, v] of vals) {
      const at = lines.findIndex((l) => l.includes(JSON.stringify(v).slice(1, -1)));
      spans.push([at >= 0 ? at + 1 : 0, v]);
    }
  }
  return { spans, error: null };
}

export function scanText(path, text, entries) {
  const hits = [];
  const full = entries.filter((e) => e.kind !== 'product-only' && e.rx);
  const po = entries.filter((e) => e.kind === 'product-only' && e.rx);
  text.split('\n').forEach((l, i) => {
    const n = normScan(l);
    for (const e of full) { e.rx.lastIndex = 0; for (const m of n.matchAll(e.rx)) hits.push({ path, line: i + 1, id: e.id, group: e.group, match: m[0], col: m.index, norm: n }); }
  });
  if (po.length) {
    const { spans, error } = productSpans(path, text);
    if (error) hits.push({ path, line: 0, id: 'UNSCANNABLE', group: '-', match: error });
    for (const [line, v] of spans) {
      const n = normScan(v);
      for (const e of po) { e.rx.lastIndex = 0; for (const m of n.matchAll(e.rx)) hits.push({ path, line, id: e.id, group: e.group, match: m[0], productPosition: true }); }
    }
  }
  return hits;
}
export function scanPath(path, entries) {
  const hits = [];
  const n = normScan(path);
  for (const e of entries) {
    if (!e.rx) continue;
    if (e.kind === 'product-only') {
      if (!path.startsWith('docs/examples/')) continue;
      const segs = path.slice('docs/examples/'.length).split('/');
      for (const s of segs) { e.rx.lastIndex = 0; if (e.rx.test(normScan(s))) hits.push({ path, line: 0, id: e.id, group: e.group, match: s, productPosition: true }); }
      continue;
    }
    e.rx.lastIndex = 0;
    for (const m of n.matchAll(e.rx)) hits.push({ path, line: 0, id: e.id, group: e.group, match: m[0] });
  }
  return hits;
}

// ---------- config: CPO approval pin + references-section allowlist (R-79, quality §7.5, M-61) ----------
const CONFIG_KEYS = ['format', 'approval', 'references'];
const APPROVAL_KEYS = ['listPath', 'sha256', 'version', 'entries', 'cpoVerdict', 'ctoConfirm', 'formatSha256', 'validatorSha256'];
const REF_KEYS = ['path', 'line', 'text', 'lineSha256', 'sourceTag', 'approver', 'beginAnchor', 'endAnchor'];
const FORBIDDEN_REF_PREFIXES = ['src/', 'packages/', 'test/', 'tests/', 'docs/examples/', 'tools/', 'verify/'];
const exactKeys = (o, keys) => o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));

export function validateConfig(cfg, listMeta, files) {
  const errs = [];
  if (!exactKeys(cfg, CONFIG_KEYS)) return ['config: keys must be exactly format, approval, references (any further exemption key is red, M-61)'];
  if (cfg.format !== CONFIG_FORMAT) errs.push('config: wrong format');
  const a = cfg.approval;
  if (!exactKeys(a, APPROVAL_KEYS)) errs.push('config: approval keys wrong');
  else {
    if (a.listPath !== LIST_PATH) errs.push('config: approval.listPath must be the exact list path');
    if (listMeta && a.sha256 !== listMeta.sha256) errs.push(`approval pin: list sha256 ${listMeta.sha256} != CPO-approved ${a.sha256} (unreviewed list change, R-79 / M-71 c)`);
    if (listMeta && a.version !== listMeta.version) errs.push(`approval pin: list version ${listMeta.version} != approved ${a.version}`);
    if (listMeta && a.entries !== listMeta.entries.length) errs.push(`approval pin: entry count ${listMeta.entries.length} != approved ${a.entries}`);
    for (const k of ['cpoVerdict', 'ctoConfirm']) if (typeof a[k] !== 'string' || !a[k].trim()) errs.push(`approval: ${k} missing`);
  }
  if (!Array.isArray(cfg.references)) errs.push('config: references must be an array');
  else cfg.references.forEach((r, i) => {
    const R = `references[${i}]`;
    if (!exactKeys(r, REF_KEYS)) { errs.push(`${R}: keys must be exactly ${REF_KEYS.join(', ')} (M-61)`); return; }
    if (typeof r.path !== 'string' || /[*?[\]{}]/.test(r.path) || r.path.endsWith('/') || r.path.startsWith('/') || r.path.includes('..')) errs.push(`${R}: path must be one exact repo-relative file path, no globs (M-61)`);
    if (EXEMPT_PATHS.includes(r.path) || r.path === CONFIG_PATH) errs.push(`${R}: cannot reference the exempt/config paths (M-61)`);
    if (FORBIDDEN_REF_PREFIXES.some((p) => String(r.path).startsWith(p))) errs.push(`${R}: no source/test/example/tools exemption via references (M-61)`);
    if (typeof r.approver !== 'string' || r.approver !== 'CPO') errs.push(`${R}: approver must be CPO (M-61)`);
    if (typeof r.sourceTag !== 'string' || !r.sourceTag.trim()) errs.push(`${R}: source tag missing (M-71 b)`);
    const body = files?.get(r.path);
    if (body === undefined) { errs.push(`${R}: path not tracked (stale entry, M-61)`); return; }
    const lines = body.split('\n');
    const ln = lines[r.line - 1];
    if (ln === undefined) { errs.push(`${R}: line out of range (stale, M-61)`); return; }
    if (sha256(Buffer.from(ln, 'utf8')) !== r.lineSha256) errs.push(`${R}: line hash stale (M-61)`);
    if (!ln.includes(r.text)) errs.push(`${R}: text not on the pinned line (M-61)`);
    if (typeof r.sourceTag === 'string' && r.sourceTag && !ln.includes(r.sourceTag)) errs.push(`${R}: source tag not on the cited line (M-71 b)`);
    const b = lines.findIndex((l) => l === r.beginAnchor);
    const e = lines.findIndex((l, k) => k > b && l === r.endAnchor);
    if (b < 0 || e < 0 || !(r.line - 1 > b && r.line - 1 < e)) errs.push(`${R}: citation outside its exact references-section anchors (M-61)`);
  });
  return errs;
}
function referenceCovers(refs, h) {
  return refs.some((r) => r.path === h.path && r.line === h.line && h.line > 0);
}

// ---------- fixture ----------
export function decodeFixture(buf) {
  let j;
  try { j = JSON.parse(buf.toString('utf8')); } catch { return { error: 'fixture: not JSON' }; }
  if (!exactKeys(j, ['format', 'cases']) || j.format !== FIXTURE_FORMAT || !Array.isArray(j.cases) || !j.cases.length) return { error: 'fixture: wrong shape' };
  for (const c of j.cases) if (!exactKeys(c, ['group', 'path', 'text']) || !GROUPS.has(c.group)) return { error: 'fixture: bad case' };
  // Raw bytes must stay escaped: no case text may appear literally in the fixture file.
  const raw = buf.toString('utf8');
  if (j.cases.some((c) => /[a-z]{3,}/i.test(c.text) && raw.includes(c.text))) return { error: 'fixture: case text stored unescaped' };
  return { cases: j.cases };
}
export function fixtureSelfTest(fixtureBuf, entries) {
  const d = decodeFixture(fixtureBuf);
  if (d.error) return { ok: false, detail: d.error };
  const dir = mkdtempSync(join(tmpdir(), 'rule40-fixture-'));
  const groups = new Set();
  const ids = new Set();
  try {
    d.cases.forEach((c, i) => {
      const p = join(dir, `case-${i}`, c.path);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, c.text);
      const hs = [...scanText(c.path, readFileSync(p, 'utf8'), entries), ...scanPath(c.path, entries)];
      if (hs.length) { groups.add(c.group); hs.forEach((h) => ids.add(h.id)); }
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const missingGroups = [...GROUPS].filter((g) => !groups.has(g));
  const missingPO = entries.filter((e) => e.kind === 'product-only' && !ids.has(e.id)).map((e) => e.id);
  return { ok: !missingGroups.length && !missingPO.length && !existsSync(dir), detail: `groups hit ${groups.size}/9${missingGroups.length ? ` missing ${missingGroups}` : ''}; product-only hit${missingPO.length ? ` missing ${missingPO}` : ' all'}; scratch removed ${!existsSync(dir)}` };
}

// ---------- whole-tree scan ----------
// files: Map<path, Buffer> of every tracked path (index bytes). Returns { configErrors, hits, report }.
export function scanTree(files) {
  const configErrors = [];
  const hits = [];
  const listBuf = files.get(LIST_PATH);
  let entries = [];
  let listMeta = null;
  if (!listBuf) configErrors.push(`list: ${LIST_PATH} is not tracked`);
  else {
    const { errors, meta } = parseList(listBuf);
    errors.forEach((e) => configErrors.push(`list: ${e}`));
    listMeta = meta;
    entries = meta.entries.filter((e) => e.rx);
  }
  let cfg = null;
  const cfgBuf = files.get(CONFIG_PATH);
  if (!cfgBuf) configErrors.push(`config: ${CONFIG_PATH} is not tracked`);
  else { try { cfg = JSON.parse(cfgBuf.toString('utf8')); } catch { configErrors.push('config: not JSON'); } }
  const texts = new Map();
  const unscannable = [];
  for (const [p, b] of files) {
    try { texts.set(p, new TextDecoder('utf-8', { fatal: true }).decode(b)); } catch { if (!BINARY_ALLOWLIST.includes(p)) unscannable.push(p); }
  }
  if (cfg) validateConfig(cfg, listMeta, texts).forEach((e) => configErrors.push(e));
  if (cfg && Array.isArray(cfg.references)) {
    const raw = cfgBuf.toString('utf8');
    cfg.references.forEach((r, i) => { if (typeof r?.text === 'string' && /[a-z]{3,}/i.test(r.text) && raw.includes(r.text)) configErrors.push(`references[${i}]: text stored unescaped in ${CONFIG_PATH} (must be \\u-escaped)`); });
  }
  const fixBuf = files.get(FIXTURE_PATH);
  let fixture = { ok: false, detail: 'not run' };
  if (!fixBuf) configErrors.push(`fixture: ${FIXTURE_PATH} is not tracked`);
  else if (entries.length) { fixture = fixtureSelfTest(fixBuf, entries); if (!fixture.ok) configErrors.push(`fixture: ${fixture.detail}`); }
  const refs = cfg && Array.isArray(cfg.references) ? cfg.references : [];
  for (const p of unscannable) hits.push({ path: p, line: 0, id: 'UNSCANNABLE', group: '-', match: 'not UTF-8 and not on the binary allowlist (RQ-FC-23)' });
  for (const [p] of files) {
    hits.push(...scanPath(p, entries));
    if (EXEMPT_PATHS.includes(p)) continue; // exact path only; content handled as config / fixture above
    const t = texts.get(p);
    if (t === undefined) continue;
    for (const h of scanText(p, t, entries)) if (!referenceCovers(refs, h)) hits.push(h);
  }
  const report = {
    listVersion: listMeta?.version ?? null, listSha256: listMeta?.sha256 ?? null, listEntries: listMeta?.entries.length ?? 0,
    approvedSha256: cfg?.approval?.sha256 ?? null, cpoVerdict: cfg?.approval?.cpoVerdict ?? null,
    exemptPaths: EXEMPT_PATHS.filter((p) => files.has(p)).map((p) => `${p}@${sha256(files.get(p)).slice(0, 8)}`),
    references: refs.length, files: files.size, fixture: fixture.detail,
  };
  return { configErrors, hits, report };
}

export function stagedFiles(root) {
  const names = execFileSync('git', ['ls-files', '--cached', '-z'], { cwd: root }).toString('utf8').split('\0').filter(Boolean);
  const files = new Map();
  for (const n of names) files.set(n, execFileSync('git', ['cat-file', 'blob', `:${n}`], { cwd: root, maxBuffer: 1 << 28 }));
  return files;
}

function main() {
  const root = new URL('../..', import.meta.url).pathname;
  const args = process.argv.slice(2);
  const self = sha256(readFileSync(new URL(import.meta.url)));
  let files = stagedFiles(root);
  if (args.includes('--worktree')) files = new Map([...files.keys()].filter((p) => existsSync(join(root, p))).map((p) => [p, readFileSync(join(root, p))]));
  const { configErrors, hits, report } = scanTree(files);
  if (args.includes('--self-test')) {
    console.log(`rule40 self-test: ${report.fixture}`);
    process.exit(configErrors.some((e) => e.startsWith('fixture')) || !/9\/9/.test(report.fixture) ? 1 : 0);
  }
  configErrors.forEach((e) => console.log(`CONFIG ${e}`));
  hits.forEach((h) => console.log(`NAMED_GAME_REFERENCE ${h.path}:${h.line}: ${h.id} ${h.group}${h.productPosition ? ' (product position)' : ''} "${h.match}"`));
  console.log(`rule40: list version ${report.listVersion} sha256 ${report.listSha256} entries ${report.listEntries}; approved ${report.approvedSha256} (${report.cpoVerdict}); exempt ${report.exemptPaths.join(', ')}; references ${report.references}; fixture ${report.fixture}; files ${report.files}; config errors ${configErrors.length}; hits ${hits.length}; scanner sha256 ${self}`);
  process.exit(configErrors.length ? 2 : hits.length ? 1 : 0);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
