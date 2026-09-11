import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = process.argv[2];
if (!build || !path.isAbsolute(build)) throw new Error('pass the absolute first-build directory from verify-zk-rebuild');
const run = await mkdtemp(path.join(build, 'candidate-matrix-'));
const require = createRequire(import.meta.url);
const ref = require('../zk-candidate/scripts/reference_v2.js');
await ref.init();
const ctx = ref.makeContextId({protocolId:1n,ledgerId:42n,chainId:1n,contractAddress:123n,version:2n});
const secretA=12345n, secretB=67890n, assetType=7n, fee=5n, recipient=123n, relayer=456n;
const note=(amount,pk,nonce)=>ref.makeNote({amount,assetType,ownerPubKey:pk,nonce,blinding:nonce+100n});
const a=note(700n,ref.ownerPubKey(secretA),1n), b=note(300n,ref.ownerPubKey(secretB),2n);
const outputs=[note(950n,ref.ownerPubKey(999n),10n),note(45n,a.ownerPubKey,11n)];
const tree=ref.buildTree([ref.commitmentHash(a),ref.commitmentHash(b)]);
const good=ref.buildJoinSplit({inputs:[{note:a,ownerSecret:secretA,index:0},{note:b,ownerSecret:secretB,index:1}],
  outputs,tree,contextId:ctx,assetType,fee,recipient,relayer}).input;
const copy=()=>structuredClone(good);
const checks=[];
const logger={info(){},debug(){},warn(){},error(){}};
async function check(name,input,accept,dir=build,basename='confidential_ledger_v2') {
  // Avoid the snarkjs file-descriptor leak when a negative witness calculation throws.
  const witness={type:'mem'};
  let accepted;
  try { await snarkjs.wtns.calculate(input,path.join(dir,basename+'_js',basename+'.wasm'),witness);
    accepted=await snarkjs.wtns.check(path.join(dir,basename+'.r1cs'),witness,logger); }
  catch(error) {
    // Missing tools/files, OOM or integration exceptions must not masquerade as constraint rejection.
    if (!/Assert Failed|assert failed/.test(String(error.message))) throw error;
    accepted=false;
  }
  assert.equal(accepted,accept,name); checks.push({name,accepted,expected:accept});
}
function refresh(input, out) {
  const commitments=out.map(ref.noteCommitment);
  input.outputAmount=out.map(n=>String(n.amount));
  input.outputCommitmentX=commitments.map(c=>String(c[0])); input.outputCommitmentY=commitments.map(c=>String(c[1]));
  input.transactionHash=String(ref.transactionHash({contextId:ctx,merkleRoot:BigInt(input.merkleRoot),assetType,fee,
    recipient,relayer,nullifiers:input.inputNullifiers.map(BigInt),outCommitments:commitments}));
}
await check('valid',good,true);
const owner=copy(); owner.inputOwnerSecret[0]='88888'; await check('wrong-owner',owner,false);
const inflated=copy(); refresh(inflated,[{...outputs[0],amount:1050n},outputs[1]]);
await check('inflation-consistent-commitments',inflated,false);
const duplicate=copy();
for(const field of ['inputAmount','inputOwnerPubKey','inputOwnerSecret','inputNonce','inputBlinding','pathElements','pathDirections','inputNullifiers']) duplicate[field][1]=structuredClone(duplicate[field][0]);
refresh(duplicate,[{...outputs[0],amount:1350n},outputs[1]]);
await check('duplicate-balanced-inputs',duplicate,false);
const destination=copy(); destination.recipient='124'; await check('changed-recipient-stale-hash',destination,false);
const merkle=copy(); merkle.pathDirections[0][0]='2'; await check('nonboolean-path-not-isolated',merkle,false);

// Mutation controls isolate the mechanism: each otherwise valid adversarial input must become
// satisfiable only in its single-constraint-removed test variant. Candidate source is never edited.
const bin=process.env.RWA_CIRCOM_BIN;
if (!bin || !path.isAbsolute(bin)) throw new Error('RWA_CIRCOM_BIN required for isolation controls');
assert.equal(execFileSync(bin,['--version'],{encoding:'utf8',timeout:10000}).trim(),'circom compiler 2.1.6');
const source=await readFile(path.join(root,'zk-candidate/circuits/confidential_ledger_v2.circom'),'utf8');
for(const [name,anchor,input] of [
  ['without-distinctness','nullifiersEqual.out === 0;',duplicate],
  ['without-conservation','inputAmount[0] + inputAmount[1] === outputAmount[0] + outputAmount[1] + fee;',inflated]
]) {
  assert.equal(source.split(anchor).length,2);
  const dir=path.join(run,name); await mkdir(dir);
  const filename=path.join(dir,'variant.circom');
  await writeFile(filename,source.replace(anchor,'// omitted only for isolated regression control'),{flag:'wx'});
  execFileSync(bin,[filename,'--r1cs','--wasm','-l',path.join(root,'node_modules'),'-o',dir],{timeout:180000,stdio:'pipe'});
  await check(name,input,true,dir,'variant');
}
await writeFile(path.join(run,'candidate-matrix-report.json'),JSON.stringify({status:'PASS',checks,
  boundary:'8 candidate R1CS checks including 2 mechanism-isolation controls; no production ceremony or independent security audit'},null,2)+'\n',{flag:'wx',mode:0o600});
console.log('ZK_CANDIDATE_MATRIX_PASS '+checks.length);
console.log('Matrix report: '+run);
// snarkjs worker threads may keep the event loop alive after completed checks.
process.exit(0);
