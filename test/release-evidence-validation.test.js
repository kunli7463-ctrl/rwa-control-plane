import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,symlink,rm,mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { validateNpmAudit,verifySourceManifest,collectSourceInventory } from '../src/release-evidence-validation.js';

const clean=()=>({auditReportVersion:2,vulnerabilities:{},metadata:{vulnerabilities:{info:0,low:0,moderate:0,high:0,critical:0,total:0}}});
test('audit evidence requires a complete consistent report, not just successful process exit',()=>{
  assert.deepEqual(validateNpmAudit(clean(),0),{total:0,clean:true});
  for(const report of [{},{error:{}},{...clean(),vulnerabilities:null}]) assert.throws(()=>validateNpmAudit(report,0));
  assert.throws(()=>validateNpmAudit(clean(),1)); assert.throws(()=>validateNpmAudit(clean(),2));
  const bad=clean();bad.metadata.vulnerabilities.total=1;assert.throws(()=>validateNpmAudit(bad,0));
});
test('known audit findings cannot be relabelled as a clean exit',()=>{
  const found=clean();found.vulnerabilities.example={severity:'high'};
  found.metadata.vulnerabilities.high=1;found.metadata.vulnerabilities.total=1;
  assert.equal(validateNpmAudit(found,1).clean,false); assert.throws(()=>validateNpmAudit(found,0));
  found.vulnerabilities.example.severity='low';assert.throws(()=>validateNpmAudit(found,1),/severity counts/);
});
test('source verifier accepts intact required files then rejects duplicate inventory entries',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'rwa-intact-test-'));
  try{
    await mkdir(path.join(root,'scripts'));
    const files=[];
    for(const name of ['package.json','package-lock.json','Dockerfile','.dockerignore','scripts/verify-internal.sh']){
      await writeFile(path.join(root,name),'fixture');
      files.push({path:name,sha256:createHash('sha256').update('fixture').digest('hex')});
    }
    const manifest={schema:'rwa.source-inventory.v1',files};
    assert.equal((await verifySourceManifest(root,manifest)).checked,5);
    await writeFile(path.join(root,'scripts','new.js'),'new source');
    await assert.rejects(verifySourceManifest(root,manifest),/unlisted source/);
    const complete={...manifest,files:await collectSourceInventory(root)};
    assert.equal((await verifySourceManifest(root,complete)).checked,6);
    await writeFile(path.join(root,'.env'),'not archived');
    assert.equal((await verifySourceManifest(root,complete)).checked,6);
    files.push(files[0]);await assert.rejects(verifySourceManifest(root,manifest),/duplicate/);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('source verifier detects changed bytes, paths and symlinks without following external targets',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'rwa-source-test-'));
  try {
    await writeFile(path.join(root,'a.js'),'one');
    const entry={path:'a.js',sha256:createHash('sha256').update('one').digest('hex')};
    const manifest={schema:'rwa.source-inventory.v1',files:[entry]};
    await assert.rejects(verifySourceManifest(root,manifest),/missing mandatory/);
    await writeFile(path.join(root,'a.js'),'two');
    await assert.rejects(verifySourceManifest(root,manifest),/source drift/);
    await assert.rejects(verifySourceManifest(root,{...manifest,files:[{...entry,path:'../a.js'}]}),/unsafe/);
    await rm(path.join(root,'a.js')); await symlink('/nonexistent-external-file',path.join(root,'a.js'));
    await assert.rejects(verifySourceManifest(root,manifest),/invalid source/);
    await assert.rejects(verifySourceManifest(root,{...manifest,files:[{path:'a.js',type:'symlink-not-followed',target:'/nonexistent-external-file'}]}),/symlink target/);
  } finally {await rm(root,{recursive:true,force:true});}
});
