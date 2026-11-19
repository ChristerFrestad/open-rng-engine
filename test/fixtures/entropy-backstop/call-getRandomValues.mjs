// Minimal caller used by entropy-backstop child-process fixtures.
const buf = new Uint8Array(8);
globalThis.crypto.getRandomValues(buf);
