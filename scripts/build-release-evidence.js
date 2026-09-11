import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateNpmAudit, verifySourceManifest, collectSourceInventory } from '../src/release-evidence-validation.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npmCLI = process.env.RWA_NPM_CLI ?? path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const lockBytes = await readFile(path.join(root, 'package-lock.json'));
const lock = JSON.parse(lockBytes);
const packages = Object.entries(lock.packages).filter(([name]) => name);
for (const [name, entry] of packages) {
  const url = new URL(entry.resolved);
  if (url.origin !== 'https://registry.npmjs.org' || url.username || url.password || url.search || url.hash
    || !/^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity ?? '')) throw new Error('unapproved dependency origin or integrity: ' + name);
}
function npmJSON(args) {
  const run = spawnSync(process.execPath, [npmCLI, ...args, '--cache', path.join(root,'.local','npm-evidence-cache'), '--fetch-retries=0', '--fetch-timeout=15000'], { cwd: root, encoding: 'utf8',
    timeout: 25000, maxBuffer: 16 * 1024 * 1024 });
  if (run.error || run.signal) throw new Error('npm evidence command failed: ' + (run.error?.code ?? run.signal));
  let result;
  try { result = JSON.parse(run.stdout); } catch { throw new Error('npm returned no valid JSON evidence'); }
  if (result.error || ![0,1].includes(run.status)) throw new Error('npm command did not produce an actionable report');
  return { exitCode: run.status, report: result };
}
function audit(args) {
  try { const outcome = npmJSON(args); validateNpmAudit(outcome.report,outcome.exitCode); return outcome; }
  catch { return { exitCode: 2, report: { status: 'NEEDS_ONLINE_VERIFICATION', reason: 'registry query failed or timed out; not a zero-vulnerability result' } }; }
}
const productionAudit = audit(['audit','--omit=dev','--json']);
const fullAudit = audit(['audit','--json']);
const bom = npmJSON(['sbom','--package-lock-only','--sbom-format=cyclonedx','--sbom-type=application']);
if (bom.exitCode !== 0 || bom.report.bomFormat !== 'CycloneDX') throw new Error('SBOM generation failed');
// Allowlist only. Never archive .env, local keys, database dumps or local tool/runtime directories.
const files = await collectSourceInventory(root);
await verifySourceManifest(root,{schema:'rwa.source-inventory.v1',files});
const date = new Date().toISOString();
const dir = path.join(root, 'release-evidence', date.replace(/[:.]/g, '-'));
await mkdir(dir, { recursive: true, mode: 0o700 });
const artifacts = { 'sbom.cyclonedx.json': bom.report, 'npm-audit-production.json': productionAudit.report,
  'npm-audit-all.json': fullAudit.report, 'source-manifest.json': { schema: 'rwa.source-inventory.v1', files },
  'summary.json': { schema: 'rwa.release-evidence.v1', generatedAt: date, node: process.version,
    packageLockSHA256: sha256(lockBytes), dependencyCount: packages.length, sourceFileCount: files.length,
    productionAuditExitCode: productionAudit.exitCode, fullAuditExitCode: fullAudit.exitCode,
    status: 'EVIDENCE_ONLY_NOT_RELEASE_APPROVAL',
    exclusions: ['host binaries','container OS','external providers','trusted ceremony','independent audit','runtime data'],
    pending: ['review dependency licenses/advisories','review artifact provenance','production deployment acceptance','independent security approval'] } };
for (const [name, content] of Object.entries(artifacts)) await writeFile(path.join(dir, name), JSON.stringify(content,null,2)+'\n', { flag:'wx', mode:0o600 });
console.log('Release evidence: ' + dir);
console.log('Production audit exit: ' + productionAudit.exitCode + '; all dependencies audit exit: ' + fullAudit.exitCode);
if (productionAudit.exitCode || fullAudit.exitCode) process.exitCode = 2;
