# Local-only Groth16 regression vector

These files prove that the application calls the real `snarkjs@0.7.6`
Groth16/BN254 verifier with the exact 13-signal JoinSplit ABI.

They were generated from `confidential_ledger_v2.circom` with Circom 2.1.6,
`circomlib@2.0.5`, and a local single-machine test ceremony. The proving key and
ceremony secrets are intentionally not part of this directory.

**Never deploy this verification key or treat this test ceremony as a trusted
production setup.** A production circuit freeze, independent audit, reproducible
build, multi-party ceremony, artifact publication and governance approval remain
mandatory.
