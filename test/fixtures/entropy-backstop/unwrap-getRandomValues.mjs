// Restore a non-wrapper getRandomValues so teardown must fail.
const crypto = (await import('node:crypto')).default ?? (await import('node:crypto'));
const c = (await import('node:crypto'));
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const cjs = require('node:crypto');
const passthrough = (arr) => arr;
for (const [obj, key] of [
  [cjs, 'getRandomValues'],
  [cjs.webcrypto, 'getRandomValues'],
  [globalThis.crypto, 'getRandomValues'],
]) {
  try { Object.defineProperty(obj, key, { configurable: true, writable: true, value: passthrough }); } catch { try { obj[key] = passthrough; } catch {} }
}
// Exit normally; the backstop beforeExit hook must flip the exit code.
