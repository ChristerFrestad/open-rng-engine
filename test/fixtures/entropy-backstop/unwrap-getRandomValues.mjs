// Attempt to restore a non-wrapper getRandomValues. Hooks are installed
// non-writable and non-configurable (G-29), so the write must not stick.
// A subsequent call is still checked; teardown also checks identity.
const { createRequire } = await import('node:module');
const require = createRequire(import.meta.url);
const cjs = require('node:crypto');
const passthrough = (arr) => arr;
for (const [obj, key] of [
  [cjs, 'getRandomValues'],
  [cjs.webcrypto, 'getRandomValues'],
  [globalThis.crypto, 'getRandomValues'],
  [typeof Crypto === 'function' ? Crypto.prototype : null, 'getRandomValues'],
]) {
  if (!obj) continue;
  try { Object.defineProperty(obj, key, { configurable: true, writable: true, value: passthrough }); } catch { try { obj[key] = passthrough; } catch {} }
}
cjs.webcrypto.getRandomValues(new Uint8Array(1));
