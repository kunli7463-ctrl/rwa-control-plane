import { readFile, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = process.env.RWA_CIRCOM_BIN;
if (!bin || !path.isAbsolute(bin)) {
  console.error('NEEDS_RUNTIME_VERIFICATION: set absolute RWA_CIRCOM_BIN for Circom 2.1.6; no build claimed');
  process.exitCode = 2;
} else {
  const version = execFileSync(bin, ['--version'], { encoding:'utf8', timeout:10000 }).trim();
  if (version !== 'circom compiler 2.1.6') throw new Error('unapproved Circom version');
  const lib = JSON.parse(await readFile(path.join(root,'node_modules/circomlib/package.json'),'utf8'));
  if (lib.version !== '2.0.5') throw new Error('unapproved circomlib version');
  const local = path.join(root,'.local'); await mkdir(local,{recursive:true});
  const output = await mkdtemp(path.join(local,'zk-rebuild-'));
  const source = path.join(root,'zk-candidate/circuits/confidential_ledger_v2.circom');
  const hash = async f => createHash('sha256').update(await readFile(f)).digest('hex');
  const builds = [];
  for (const name of ['first','second']) {
    const dir = path.join(output,name); await mkdir(dir);
    execFileSync(bin,[source,'--r1cs','--wasm','--sym','-l',path.join(root,'node_modules'),'-o',dir],
      {cwd:root,timeout:180000,stdio:'pipe',maxBuffer:8*1024*1024});
    const hashes = {};
    for (const file of ['confidential_ledger_v2.r1cs','confidential_ledger_v2.sym','confidential_ledger_v2_js/confidential_ledger_v2.wasm']) hashes[file] = await hash(path.join(dir,file));
    builds.push(hashes);
  }
  const equal = JSON.stringify(builds[0]) === JSON.stringify(builds[1]);
  const report = {schema:'rwa.zk-rebuild.v1', compilerVersion:version, compilerSHA256:await hash(bin),
    sourceSHA256:await hash(source), packageLockSHA256:await hash(path.join(root,'package-lock.json')),
    sameHostByteIdentical:equal, builds, status:equal?'LOCAL_REBUILD_ONLY_NOT_SECURITY_APPROVAL':'REBUILD_MISMATCH',
    notVerified:['cross-host reproducibility','witness constraint completeness','production ceremony','existing verification key source linkage','independent audit']};
  await writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('ZK rebuild evidence: '+output);
  if (!equal) process.exitCode=1;
}
