import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Report findings without silently excluding unfixed, unknown or disputed CVEs.
// This gate intentionally is not an automatic risk-acceptance mechanism.
const report = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.equal(report.SchemaVersion, 2);
assert.equal(report.ArtifactType, 'container_image');
assert.match(report.Metadata?.ImageID ?? '', /^sha256:[a-f0-9]{64}$/);
const age = Date.now() - Date.parse(report.CreatedAt);
assert.ok(Number.isFinite(age) && age >= -300000 && age <= 48*60*60*1000, 'fresh scan timestamp required');
assert.ok(Array.isArray(report.Results) && report.Results.some(r => r.Class === 'os-pkgs'));
const totals = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
const results = report.Results.map(result => {
  assert.ok(result.Vulnerabilities === undefined || Array.isArray(result.Vulnerabilities));
  const counts = { ...totals };
  for (const key of Object.keys(counts)) counts[key] = 0;
  for (const item of result.Vulnerabilities ?? []) {
    assert.ok(Object.hasOwn(counts, item.Severity));
    counts[item.Severity]++; totals[item.Severity]++;
  }
  return { target: result.Target, counts,
    fixAvailable: (result.Vulnerabilities ?? []).filter(v => Boolean(v.FixedVersion)).length };
});
console.log(JSON.stringify({ imageID: report.Metadata.ImageID, scannedAt: report.CreatedAt,
  results, totals, status: Object.values(totals).some(Boolean) ? 'REVIEW_REQUIRED' : 'NO_REPORTED_FINDINGS',
  boundary: 'package-level scanner results, not exploitability or production approval' }, null, 2));
if (Object.values(totals).some(Boolean)) process.exitCode = 2;
