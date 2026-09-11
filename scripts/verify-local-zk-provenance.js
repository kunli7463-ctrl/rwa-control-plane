import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import * as snarkjs from 'snarkjs';

// Rebuild a separate UNSAFE LOCAL TEST setup. Never overwrite the historical
// fixture or present this single-machine test setup as secure.
const [build, ptau, inputFile] = process.argv.slice(2);
for (const arg of [build, ptau, inputFile]) assert.ok(arg && path.isAbsolute(arg));
assert.ok(path.basename(ptau).startsWith('UNSAFE_TEST_ONLY_'));
const output = await mkdtemp(path.join(path.dirname(ptau), 'source-chain-'));
const r1cs = path.join(build, 'confidential_ledger_v2.r1cs');
const wasm = path.join(build, 'confidential_ledger_v2_js/confidential_ledger_v2.wasm');
const key = path.join(output, 'UNSAFE_TEST_ONLY.zkey');
const input = JSON.parse(await readFile(inputFile, 'utf8'));
const sha = async file => createHash('sha256').update(await readFile(file)).digest('hex');
const report = { schema: 'rwa.local-zk-provenance.v1', startedAt: new Date().toISOString(),
  productionApproved: false, ceremony: 'UNSAFE_SINGLE_MACHINE_LOCAL_TEST_ONLY',
  historicalFixtureSourceLink: 'NOT_ESTABLISHED', checks: [] };
const save = (name, value) => writeFile(path.join(output, name), JSON.stringify(value,null,2)+'\n', {flag:'wx',mode:0o600});
try {
  console.log('Building local-only zkey from supplied R1CS and test PTAU');
  await snarkjs.zKey.newZKey(r1cs, ptau, key);
  assert.equal(await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, key), true);
  report.checks.push('zkey_matches_r1cs_and_test_ptau');
  const vk = await snarkjs.zKey.exportVerificationKey(key);
  assert.equal(vk.nPublic, 13);
  await save('verification_key.json', vk);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input.circuitInput, wasm, key);
  assert.deepEqual(publicSignals, input.expectedPublicSignals);
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  report.checks.push('new_proof_matches_all_13_expected_signals_and_exported_key');
  await save('valid_proof.json', proof);
  await save('public_signals.json', publicSignals);
  report.hashes = { r1cs:await sha(r1cs), wasm:await sha(wasm), ptau:await sha(ptau),
    zkey:await sha(key), verificationKey:await sha(path.join(output,'verification_key.json')),
    input:await sha(inputFile), proof:await sha(path.join(output,'valid_proof.json')) };
  report.status = 'LOCAL_SOURCE_CHAIN_VERIFIED_NOT_SECURITY_APPROVAL';
} catch (error) { report.status = 'FAIL'; report.error = error.message; process.exitCode = 1; }
report.completedAt = new Date().toISOString();
await save('report.json', report);
console.log('Local provenance report: '+output);
// ffjavascript curve workers can otherwise keep this finite verification alive.
process.exit(process.exitCode ?? 0);
