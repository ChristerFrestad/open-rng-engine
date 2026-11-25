// HoQ A17 M-A17-1 / A18 N-A18-1: run a node child under a hard limit and fail loudly. A child killed by the
// limit fails with an explicit TIMEOUT message; a child that did not run (spawn error, or the
// entropy-backstop's fail-closed throw from the hooked spawnSync) or was killed by a signal fails with
// CHILD-FAILED. Never an empty-output assertion. Not a test file (no .test suffix).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

export function runChecked(label, args, { timeoutMs, cwd }) {
  let r;
  try {
    r = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', cwd });
  } catch (e) {
    // N-A18-1: under the entropy-backstop preload (npm test) a child that never ran throws from the hooked
    // spawnSync instead of returning r.error; report it the same way, never as empty output.
    assert.fail(`CHILD-FAILED: ${label} child did not run (${e?.code ?? e?.message ?? String(e)})`);
  }
  if (r.error && r.error.code === 'ETIMEDOUT') {
    assert.fail(`TIMEOUT: ${label} child killed after ${timeoutMs} ms (signal ${r.signal}); output so far:\n${r.stdout ?? ''}\n${r.stderr ?? ''}`);
  }
  if (r.error) {
    assert.fail(`CHILD-FAILED: ${label} child did not run (${r.error.code ?? r.error.message})`);
  }
  if (r.signal !== null) {
    assert.fail(`CHILD-FAILED: ${label} child killed by signal ${r.signal}; output so far:\n${r.stdout}\n${r.stderr}`);
  }
  return r;
}
