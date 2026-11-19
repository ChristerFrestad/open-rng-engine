// LICENSE exact-path + sha256 guard (CTO, CPO-R97b (3) accepted; LF-3). Shared by tools that skip the LICENSE text.
// A tool may skip LICENSE only when the path is exactly 'LICENSE' AND its bytes hash to the pinned unmodified
// Apache-2.0 text. Changed bytes are red: the file is never silently exempt.
import { createHash } from 'node:crypto';

export const LICENSE_PATH = 'LICENSE';
export const LICENSE_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';

/** @returns {{ exempt: boolean, red: boolean, sha256: string|null, detail: string }} */
export function licenseGuard(path, buf) {
  if (path !== LICENSE_PATH) return { exempt: false, red: false, sha256: null, detail: 'not the exact LICENSE path' };
  if (!buf) return { exempt: false, red: true, sha256: null, detail: 'LICENSE missing' };
  const sha256 = createHash('sha256').update(buf).digest('hex');
  if (sha256 !== LICENSE_SHA256) return { exempt: false, red: true, sha256, detail: `LICENSE altered: sha256 ${sha256} != pinned ${LICENSE_SHA256}` };
  return { exempt: true, red: false, sha256, detail: 'LICENSE unmodified (exact path + sha)' };
}
