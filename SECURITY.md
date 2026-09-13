# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue.

- Open a private advisory through the repository's Security tab
  ("Report a vulnerability"), or
- email the maintainer address listed on the repository profile.

Include what the issue lets an attacker do, the version or commit, and a
reproduction if you have one. Expect an acknowledgement within a few working
days; this project is maintained by a small team, so please allow reasonable
time before public disclosure.

## Scope

In scope: the control plane services (`src/`), database migrations and their
guards (`db/migrations/`), the settlement gate, callback verification, the
outbox and prover workers, and the deployment profiles under `deploy/`.

Out of scope, and known: the candidate circuits in `zk-candidate/` are **not
audited** and have no production ceremony; the Groth16 test vector under
`test/fixtures/groth16-local-only/` is a single-party local ceremony that must
never be deployed. Reports about those are welcome as issues, but they are
documented limitations rather than undisclosed vulnerabilities.

## What this system assumes

Reports are most useful when they break one of these stated guarantees:

- The runtime database identity cannot delete, truncate, or disable triggers on
  append-only tables, and production refuses to start if it can.
- A single principal cannot both make and check the same decision.
- A confidential transfer cannot settle to a recipient key that is not
  registered to the named, eligible recipient credential.
- A published note-tree root cannot differ from the root recomputed by the
  server from the previous root and the transaction's output commitments.
- A spent nullifier cannot be removed or replayed.
- An audit checkpoint that has been anchored externally cannot be reproduced
  after any event below it is altered or removed.

## Prior review

An independent architecture and security review was completed on 2026-09-11.
Its findings and the remediation for each are recorded in
[docs/SECURITY_REMEDIATION_2026-09-11.md](docs/SECURITY_REMEDIATION_2026-09-11.md).
