import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateNpmAudit,verifySourceManifest } from '../src/release-evidence-validation.js';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const dir=process.argv[2];
if(!dir || !path.isAbsolute(dir)) throw new Error('absolute evidence directory required');
const json=async name=>JSON.parse(await readFile(path.join(dir,name),'utf8'));
const inventory=await verifySourceManifest(root,await json('source-manifest.json'));
const summary=await json('summary.json');
const lockHash=createHash('sha256').update(await readFile(path.join(root,'package-lock.json'))).digest('hex');
if(summary.packageLockSHA256!==lockHash || summary.sourceFileCount!==inventory.checked) throw new Error('summary/source inventory drift');
let pending=false;
for(const [filename,status] of [['npm-audit-production.json',summary.productionAuditExitCode],['npm-audit-all.json',summary.fullAuditExitCode]]){
  if(status===2){pending=true;continue;}
  const audit=validateNpmAudit(await json(filename),status); if(!audit.clean)pending=true;
}
console.log('SOURCE_INVENTORY_VERIFIED '+inventory.checked);
console.log(pending?'AUDIT_GATE_NOT_CLOSED':'AUDIT_REPORTS_CLEAN_NOT_RELEASE_APPROVAL');
if(pending)process.exitCode=2;
