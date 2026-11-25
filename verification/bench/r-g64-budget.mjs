// Budget table for verification/r-g64-design.md, computed from the two committed bench runs
// (r-g64-throughput-run{1,2}.json; mean stage-C ns per public call). Core-hours to give every K entry
// 10^9 outcomes; a tuple entry of width w costs w calls per outcome. Usage: node verification/bench/r-g64-budget.mjs
import { readFileSync } from 'node:fs';
const [a, b] = ['run1', 'run2'].map((r) => JSON.parse(readFileSync(new URL(`r-g64-throughput-${r}.json`, import.meta.url), 'utf8')));
const M = 1e9;
console.log('| Call shape | K entries | Stage C ns, run 1 | Stage C ns, run 2 | Core-h per 10^9 calls | Core-h, own stream per entry | Core-h, one stream per shape |');
console.log('|---|---|---|---|---|---|---|');
let own = 0, shared = 0;
const fam = {};
a.rows.forEach((r, i) => {
  const s = b.rows[i];
  if (r.shape !== s.shape) throw new Error(`run shapes differ at ${i}`);
  const h = ((r.C.ns + s.C.ns) / 2) * M / 1e9 / 3600;
  const w = r.tuple_entries.map((x) => Number(x.split('w=')[1]));
  const I = h * (r.entries - w.length + w.reduce((x, y) => x + y, 0));
  const II = h * Math.max(1, ...w);
  own += I; shared += II;
  const f = r.shape.split(' ')[0]; fam[f] ??= [0, 0]; fam[f][0] += I; fam[f][1] += II;
  const t = w.length ? ` (${w.length} tuple, w ${[...new Set(w)].join('/')})` : '';
  console.log(`| ${r.shape} | ${r.entries}${t} | ${r.C.ns} | ${s.C.ns} | ${h.toFixed(2)} | ${I.toFixed(1)} | ${II.toFixed(1)} |`);
});
console.log(`| Total | 157 | | | | ${own.toFixed(0)} | ${shared.toFixed(0)} |`);
console.log('\nPer primitive (core-h, own stream / one stream per shape):');
for (const [f, [x, y]] of Object.entries(fam)) console.log(`- ${f}: ${x.toFixed(0)} / ${y.toFixed(0)}`);
console.log('\nMeasured stage-C scaling, shuffle n=52, P concurrent helpers on this box (total calls/s vs P=1):');
for (const [n, r] of [['run 1', a], ['run 2', b]]) console.log(`- ${n}: ${r.scale.map((s) => `P=${s.P} ${(s.calls_per_sec_total / r.scale[0].calls_per_sec_total).toFixed(2)}x`).join(', ')}`);
