import { readFile, lstat, readlink, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export async function collectSourceInventory(root) {
  root = path.resolve(root);
  const files = [];
  async function walk(relative) {
    const file = path.join(root, relative), stat = await lstat(file);
    if (stat.isSymbolicLink()) {
      const target = await readlink(file);
      if (!path.resolve(path.dirname(file), target).startsWith(root + path.sep)) throw new Error('external source symlink');
      files.push({path:relative,type:'symlink-not-followed',target});
    } else if (stat.isDirectory()) {
      for (const name of (await readdir(file)).sort()) await walk(path.join(relative,name));
    } else if (stat.isFile() && (['Dockerfile','.dockerignore'].includes(relative) || /\.(js|sh|sql|json|yaml|yml|md|html|css|circom)$/.test(relative)) && !/(^|\/)\.env/.test(relative)) {
      files.push({path:relative,sha256:createHash('sha256').update(await readFile(file)).digest('hex')});
    }
  }
  for (const dir of ['src','scripts','db','deploy','test','public','sdk','zk-candidate']) {
    try { await lstat(path.join(root,dir)); } catch(error) { if(error.code === 'ENOENT') continue; throw error; }
    await walk(dir);
  }
  for (const file of ['package.json','package-lock.json','Dockerfile','.dockerignore']) await walk(file);
  return files;
}
export function validateNpmAudit(report, exitCode) {
  if (!object(report) || report.auditReportVersion !== 2 || !object(report.vulnerabilities)
    || !object(report.metadata?.vulnerabilities) || ![0,1].includes(exitCode)) throw new Error('invalid audit evidence');
  const counts = report.metadata.vulnerabilities;
  let total = 0;
  for (const severity of ['info','low','moderate','high','critical']) {
    if (!Number.isSafeInteger(counts[severity]) || counts[severity] < 0) throw new Error('invalid audit counts');
    total += counts[severity];
  }
  if (!Number.isSafeInteger(total) || counts.total !== total
    || Object.keys(report.vulnerabilities).length !== total
    || (exitCode === 0) !== (total === 0)) throw new Error('inconsistent audit outcome');
  const observed={info:0,low:0,moderate:0,high:0,critical:0};
  for(const finding of Object.values(report.vulnerabilities)) {
    if(!object(finding) || !Object.hasOwn(observed,finding.severity)) throw new Error('invalid finding severity');
    observed[finding.severity]++;
  }
  for(const severity of Object.keys(observed)) if(observed[severity]!==counts[severity]) throw new Error('audit severity counts disagree');
  return { total, clean: total === 0 };
}

export async function verifySourceManifest(root, manifest) {
  if (manifest?.schema !== 'rwa.source-inventory.v1' || !Array.isArray(manifest.files) || !manifest.files.length) throw new Error('invalid source inventory');
  const seen = new Set();
  for (const entry of manifest.files) {
    if (typeof entry.path !== 'string' || path.isAbsolute(entry.path) || entry.path.includes('\\')
      || entry.path.split('/').some(part => !part || part === '.' || part === '..') || seen.has(entry.path)) throw new Error('unsafe or duplicate inventory path');
    seen.add(entry.path);
    const parts=entry.path.split('/');
    for (let i=1;i<parts.length;i++) if ((await lstat(path.join(root,...parts.slice(0,i)))).isSymbolicLink()) throw new Error('inventory parent is a symlink');
    const file = path.join(root,entry.path), stat = await lstat(file);
    if (entry.type === 'symlink-not-followed') {
      if (!stat.isSymbolicLink()) throw new Error('symlink type changed');
      const target=await readlink(file);
      if (target !== entry.target || !path.resolve(path.dirname(file),target).startsWith(path.resolve(root)+path.sep)) throw new Error('symlink target drift');
    } else {
      if (entry.type !== undefined || !stat.isFile() || stat.isSymbolicLink() || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? '')) throw new Error('invalid source file entry');
      const actual=createHash('sha256').update(await readFile(file)).digest('hex');
      if (actual !== entry.sha256) throw new Error('source drift: '+entry.path);
    }
  }
  for (const mandatory of ['package.json','package-lock.json','Dockerfile','.dockerignore','scripts/verify-internal.sh']) {
    if (!seen.has(mandatory)) throw new Error('missing mandatory source entry: '+mandatory);
  }
  const current = await collectSourceInventory(root);
  for (const entry of current) if (!seen.has(entry.path)) throw new Error('unlisted source file: '+entry.path);
  const currentPaths = new Set(current.map(entry=>entry.path));
  for (const name of seen) if (!currentPaths.has(name)) throw new Error('out-of-scope source entry: '+name);
  return {checked:seen.size};
}
