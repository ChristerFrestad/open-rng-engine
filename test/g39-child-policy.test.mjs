// G-39 at the source (HoQ 4c7adda0/f575fe1f §3.4; CTO batch D). check:ph0 runs HoQ's 8 bypasses and the
// variants in tools/ci/entropy-backstop-check.mjs and requires each to be refused. This file proves the two
// policy pieces behave as specified. The mutants (each rule off -> its bypasses reach) cannot run under
// `npm test`: the backstop forces itself into every node child, so a mutated copy can never load alone.
// They run from tools/ci/g39-mutants.mjs, outside the backstop (see tools/ci/README.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHILD_EXECUTABLE_ALLOWLIST, GIT_SUBCOMMANDS, REFUSED_BINDINGS, EVIDENCE_TOOLS, INTERPRETER, classifyChild, checkGitChild } from '../tools/ci/entropy-backstop.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

test('G-39 policy constants are the reviewed allowlists', () => {
  assert.deepEqual([...CHILD_EXECUTABLE_ALLOWLIST], ['node', 'git', 'mkdir', 'ln']);
  assert.deepEqual([...GIT_SUBCOMMANDS], ['add', 'cat-file', 'check-attr', 'check-ignore', 'checkout', 'clone', 'config', 'init', 'ls-files', 'rev-parse', 'rm', 'show', 'status']);
  assert.ok(REFUSED_BINDINGS.includes('spawn_sync') && REFUSED_BINDINGS.includes('process_wrap'));
});

test('G-39 classifyChild refuses shells, interpreters, env and script files; allows node, git, mkdir', () => {
  for (const exe of ['sh', 'bash', 'env', '/usr/bin/env', 'python3', 'perl', '/tmp/x.sh', 'dash', 'zsh', 'busybox']) {
    assert.throws(() => classifyChild('file', exe, [], {}), /child process refused/, exe);
  }
  assert.throws(() => classifyChild('shell', 'node -e 1; true', [], {}), /not one plain allowlisted command/);
  assert.throws(() => classifyChild('shell', 'X=1 node', [], {}), /not one plain allowlisted command/);
  assert.throws(() => classifyChild('file', 'node', [], { shell: '/bin/bash' }), /shell \/bin\/bash/);
  assert.throws(() => classifyChild('fork', 'x.mjs', [], { execPath: '/bin/sh' }), /fork execPath/);
  assert.equal(classifyChild('file', process.execPath, [], {}).node, true);
  assert.equal(classifyChild('file', 'mkdir', ['-p', '/tmp/x'], {}).node, false);
  assert.equal(classifyChild('file', 'git', ['ls-files'], { cwd: ROOT }).git, true);
});

test('G-39 git: global options, unlisted subcommands, program-running options and config keys are refused', () => {
  assert.throws(() => checkGitChild(['-c', 'alias.x=!sh', 'x'], { cwd: ROOT }), /git global option -c/);
  assert.throws(() => checkGitChild(['difftool'], { cwd: ROOT }), /subcommand difftool/);
  assert.throws(() => checkGitChild(['config', 'alias.x', '!sh'], { cwd: ROOT }), /user.name or user.email/);
  assert.throws(() => checkGitChild(['clone', '-u', '/tmp/x', 'a', 'b'], { cwd: ROOT }), /git option -u/);
  const d = mkdtempSync(join(tmpdir(), 'g39-git-'));
  try {
    spawnSync('git', ['init', '-q'], { cwd: d });
    writeFileSync(join(d, '.git/config'), '[core]\n\trepositoryformatversion = 0\n[filter "x"]\n\tclean = sh -c true\n');
    assert.throws(() => checkGitChild(['add', '-A'], { cwd: d }), /config key filter.x.clean/);
  } finally { rmSync(d, { recursive: true, force: true }); }
  checkGitChild(['ls-files'], { cwd: ROOT });
  checkGitChild(['-C', ROOT, 'status'], {});
});

// G-45 (HoQ report c9d7c93..dbd4e00, addendum 1 A7): the entry guard at the spawn layer. The 19 evasions run
// in check:ph0 (entropy-backstop-check); the READY-world grant path and G45-M1..M10 in g39-mutants.
test('G-45 spawn layer: evidence tools need an OK guard grant; interpreters are never spawned', async () => {
  const T = ['die' + 'harder', 'tu01' + '-driver', 'ass' + 'ess', 'RNG' + '_test'];
  assert.deepEqual([...EVIDENCE_TOOLS], T);
  for (const t of T) {
    assert.throws(() => classifyChild('file', `/opt/lab/${t}`, [], {}), /without an OK entry guard \(G-45\)/);
    assert.throws(() => classifyChild('shell', `${t} -a`, [], {}), /\(G-45\)/);
    assert.throws(() => classifyChild('file', '/usr/bin/node', ['-e', `x('${t}')`], {}), /\(G-45\)/);
  }
  for (const i of ['python3', 'python', 'perl', 'sh', 'bash', 'env', 'ruby', 'xargs', 'awk']) assert.ok(INTERPRETER.test(i), i);
  assert.throws(() => classifyChild('file', 'python3', ['-c', '1'], {}), /interpreter python3 is never spawned \(G-45\)/);
  const ev = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].evidence;
  await assert.rejects(ev.open(), /harness NOT-READY/);
  assert.throws(() => ev.launch(Object.freeze({ grant: 1 }), `/opt/lab/${T[0]}`, []), /without an open grant \(G-45\)/);
});
