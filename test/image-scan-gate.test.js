import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/summarize-image-scan.js', import.meta.url));
async function run(report) {
  const dir = await mkdtemp(path.join(tmpdir(), 'rwa-image-scan-'));
  const file = path.join(dir,'report.json');
  await writeFile(file,JSON.stringify(report));
  return spawnSync(process.execPath,[script,file],{encoding:'utf8',timeout:10000});
}
const report = () => ({ SchemaVersion:2, ArtifactType:'container_image', CreatedAt:new Date().toISOString(),
  Metadata:{ImageID:'sha256:'+'a'.repeat(64)}, Results:[{Target:'debian',Class:'os-pkgs',Vulnerabilities:[]}] });
test('image scan gate preserves unfixed findings and never treats unknown as clean', async () => {
  const input = report();
  input.Results[0].Vulnerabilities = [{Severity:'HIGH',Status:'will_not_fix'},{Severity:'UNKNOWN'}];
  const result = await run(input);
  assert.equal(result.status,2);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.totals.HIGH,1);
  assert.equal(summary.totals.UNKNOWN,1);
});
test('image scan gate rejects missing OS scan and allows an explicit empty findings list', async () => {
  const input = report();
  assert.equal((await run(input)).status,0);
  input.Results = [];
  assert.notEqual((await run(input)).status,0);
  const stale = report(); stale.CreatedAt = '2020-01-01T00:00:00Z';
  assert.notEqual((await run(stale)).status,0);
});
