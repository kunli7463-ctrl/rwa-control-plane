import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Intentionally fixed to the isolated acceptance profile; never select a
// user's default Docker context or an arbitrary remote Docker endpoint.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const endpoint = process.env.DOCKER_HOST;
assert.ok(/^unix:\/\/\/Users\/[^/]+\/\.colima\/rwa-acceptance\/docker\.sock$/.test(endpoint ?? ''), 'explicit local rwa-acceptance Docker socket required');
const names = { web:'rwa-acceptance-web-1', worker:'rwa-acceptance-outbox-worker-1', migrate:'rwa-acceptance-migrate-1', database:'rwa-acceptance-postgres-1' };
await mkdir(path.join(root,'.local'),{recursive:true});
const dir=await mkdtemp(path.join(root,'.local/container-acceptance-'));
const report={schema:'rwa.local-container-acceptance.v1',startedAt:new Date().toISOString(),scope:'ISOLATED_SYNTHETIC_POC',checks:[],productionApproved:false};
function docker(args,{allowFailure=false}={}) {
  const result=spawnSync('docker',args,{cwd:root,env:process.env,encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024});
  if(result.error || result.signal)throw Error('Docker command unavailable or timed out');
  if(!allowFailure && result.status!==0)throw Error('Docker acceptance command failed: '+args[0]);
  return result;
}
const record=name=>{report.checks.push(name);console.log('PASS '+name);};
const request=(url,options={})=>fetch(url,{...options,signal:AbortSignal.timeout(3000),redirect:'error'});
async function waitHealthy(url) {
  for(let attempt=0;attempt<60;attempt++) {
    try{if((await request(url)).ok)return;}catch{}
    await delay(500);
  }
  throw Error('acceptance health endpoint did not recover');
}
try {
  const inspect=Object.fromEntries(Object.entries(names).map(([role,name])=>[role,JSON.parse(docker(['inspect',name]).stdout)[0]]));
  for(const container of Object.values(inspect))assert.equal(container.Config.Labels['com.docker.compose.project'],'rwa-acceptance');
  assert.equal(inspect.migrate.State.ExitCode,0);
  assert.equal(inspect.migrate.State.Status,'exited');
  for(const role of ['web','worker','database'])assert.equal(inspect[role].State.Health.Status,'healthy');
  for(const role of ['web','worker']) {
    assert.equal(inspect[role].Config.User,'10001:10001');
    assert.equal(inspect[role].HostConfig.ReadonlyRootfs,true);
    for(const bindings of Object.values(inspect[role].HostConfig.PortBindings))for(const binding of bindings)assert.equal(binding.HostIp,'127.0.0.1');
    const port=role==='web'?'8765/tcp':'8770/tcp';
    assert.deepEqual(inspect[role].NetworkSettings.Ports[port],inspect[role].HostConfig.PortBindings[port], 'requested port must actually be published');
  }
  assert.equal(Object.keys(inspect.database.HostConfig.PortBindings ?? {}).length,0);
  assert.deepEqual(Object.keys(inspect.database.NetworkSettings.Networks),['rwa-acceptance_rwa-internal']);
  record('migration completed; web, worker and database healthy; non-root/read-only workloads and loopback-only exposure');
  const webPort=inspect.web.HostConfig.PortBindings['8765/tcp'][0].HostPort;
  const workerPort=inspect.worker.HostConfig.PortBindings['8770/tcp'][0].HostPort;
  assert.match(webPort,/^\d+$/);assert.match(workerPort,/^\d+$/);
  const base='http://127.0.0.1:'+webPort;
  await waitHealthy(base+'/health/ready');
  await waitHealthy('http://127.0.0.1:'+workerPort+'/readyz');
  // This named, isolated acceptance project contains disposable synthetic
  // fixtures only. Refresh them through the protected UI route, never SQL;
  // ordinary auth acceptance must not silently reset a user's database.
  const login=await request(base+'/api/sandbox/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({principalId:'issuer-console'})});
  assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie')?.split(';',1)[0];
  const session=await login.json();
  assert.equal(session.identity.tenantId,'sandbox-hk');
  assert.ok(cookie);assert.ok(session.csrfToken);
  const reset=await request(base+'/api/action',{method:'POST',headers:{'content-type':'application/json',cookie,'x-csrf-token':session.csrfToken},body:JSON.stringify({action:'reset'})});
  assert.equal(reset.status,200,'isolated synthetic fixture preparation must succeed');
  record('isolated synthetic fixtures refreshed through authenticated issuer/CSRF route');
  const auth=spawnSync(process.execPath,['scripts/verify-auth-http.js'],{cwd:root,env:{...process.env,DEMO_BASE_URL:base},encoding:'utf8',timeout:30000});
  assert.equal(auth.status,0,'HTTP auth/role-spoof/CSRF acceptance failed');
  record('real container HTTP rejects unauthenticated access, role spoofing and missing CSRF');
  docker(['exec',names.web,'node','-e',`for(const p of ['circomlibjs','ethers','elliptic','ws']){let found=false;try{require.resolve(p);found=true}catch(e){if(e.code!=='MODULE_NOT_FOUND')throw e}if(found)throw Error('development package entered runtime: '+p)}console.log('PRODUCTION_DEPENDENCIES_ONLY')`]);
  record('runtime image excludes circomlibjs/ethers/elliptic/ws development dependency chain');
  docker(['exec',names.web,'node','-e',`const fs=require('node:fs');for(const p of ['/usr/local/lib/node_modules/npm','/usr/local/bin/npm','/usr/local/bin/npx']){if(fs.existsSync(p))throw Error('build-only npm CLI remains in runtime')}`]);
  record('build-only npm CLI absent from runtime');
  const keyMetadata=()=>JSON.parse(docker(['exec',names.web,'node','-e',`const s=require('node:fs').statSync('/var/lib/rwa-control-plane/dev-encryption-key.json');console.log(JSON.stringify({uid:s.uid,gid:s.gid,mode:s.mode&511,size:s.size,ino:s.ino,mtime:s.mtimeMs}))`]).stdout);
  const before=keyMetadata();assert.equal(before.uid,10001);assert.equal(before.mode,0o600);assert.ok(before.size>0);
  docker(['restart',names.web]);
  await waitHealthy(base+'/health/ready');
  assert.deepEqual(keyMetadata(),before);
  record('web restart recovers readiness and preserves existing 0600 development key without reading its value');
  const negative=docker(['run','--rm','--network','none','--read-only',inspect.web.Image],{allowFailure:true});
  assert.notEqual(negative.status,0);
  assert.match(negative.stderr,/PRODUCTION_PROFILE_REQUIRED|NODE_ENV=production requires DEPLOYMENT_PROFILE=production/);
  record('default production image fails closed without an explicit production deployment profile');
  report.images=Object.fromEntries(Object.entries(inspect).map(([role,c])=>[role,c.Image]));
  report.runtime=docker(['exec',names.web,'node','--version']).stdout.trim();
  report.status='PASS';
}catch(error){report.status='FAIL';report.error=error.message;process.exitCode=1;}
finally {
  report.completedAt=new Date().toISOString();
  await writeFile(path.join(dir,'report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('Container acceptance report: '+dir);
}
