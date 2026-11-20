// G-64 (HoQ A9): static ban on defining the entropy-backstop marker outside the backstop. A file outside test/
// that names the marker symbol and also defines or assigns a global property is a forger (HoQ probe A2).
// The launcher (evidence-launcher.mjs) is the real authority; this rule makes a planted forger visible.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

// Joined at runtime only so that this scanner, which must name both patterns, does not match itself.
const MARK_TEXT = ['open-rng-engine', 'entropy-backstop', 'v1'].join('/');
const DEFINE = /defineProperty|defineProperties|Reflect\.(?:set|defineProperty)|globalThis\s*\[[^\]]*\]\s*=(?!=)/;
export function markerBanFindings(root, { backstop = 'tools/ci/entropy-backstop.mjs' } = {}) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d)) {
      if (e === 'node_modules' || e === '.git' || e === 'npm-reserved') continue;
      const p = join(d, e); const rel = relative(root, p).split('\\').join('/');
      if (statSync(p).isDirectory()) { if (rel !== 'test') walk(p); continue; }
      if (!/\.(?:mjs|cjs|js|ts|mts|cts)$/.test(e) || rel === backstop) continue;
      const s = readFileSync(p, 'utf8');
      if (s.includes(MARK_TEXT) && DEFINE.test(s)) out.push(`${rel}: names the backstop marker and defines a global property (G-64)`);
    }
  };
  walk(root);
  return out;
}
