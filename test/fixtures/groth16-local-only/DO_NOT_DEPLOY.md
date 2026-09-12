# Local-only Groth16 regression vector

These files prove that the application calls the real `snarkjs@0.7.6`
Groth16/BN254 verifier with the exact 13-signal JoinSplit ABI, and that the
proof in this directory verifies under `verification_key.json`, whose SHA-256 is
pinned in `manifest.json`.

## Provenance (audit finding D4)

They were produced locally with Circom 2.1.6, `circomlib@2.0.5` and a
single-machine test ceremony, from what was then `confidential_ledger_v2.circom`.
**That link is asserted by the operator, not proven.** The r1cs, the proving key
and the ceremony transcript are deliberately not stored here, so nothing in this
repository shows that this verification key belongs to the circuit source in
`zk-candidate/circuits/`. `npm run zk:rebuild` reports the same limitation
("existing verification key source linkage" is listed as not verified), and
`zk-candidate/NOT_APPROVED.md` states the same conclusion. Establishing it
requires an unbroken hash chain from frozen circuit source to r1cs, zkey and
verification key, produced by a reproducible build and a recorded ceremony.

**Never deploy this verification key or treat this test ceremony as a trusted
production setup.** A production circuit freeze, independent audit, reproducible
build, multi-party ceremony, artifact publication and governance approval remain
mandatory.
