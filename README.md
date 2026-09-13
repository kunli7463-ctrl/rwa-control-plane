# RWA Control Plane

**Compliance you can prove, enforced by the database — not by process.**

An open-source control plane for tokenized fund operations. Eligibility, dual
control, transaction state and the audit trail are enforced inside PostgreSQL
under `SERIALIZABLE` transactions and append-only triggers, so a compromised
application — or a careless operator — cannot quietly rewrite history. A
confidential settlement rail (Groth16 JoinSplit) keeps amounts private while the
server still enforces who may send and receive.

> Synthetic data only. This is not a licensed financial system, and it does not
> hold or move real assets. See [Scope and limits](#scope-and-limits).

[简体中文说明](README.zh-CN.md)

## Run it in three commands

Requires a running Docker engine — Docker Desktop or OrbStack open, or
`colima start` for a Colima setup. No Node, database or key setup.

```sh
git clone <this repository> && cd rwa-control-plane
./scripts/poc-up.sh             # works with `docker compose` or `docker-compose`
open http://127.0.0.1:8765      # web demo, 12-step guided walkthrough
```

The stack starts PostgreSQL 16, applies all 32 migrations, seeds a synthetic
Hong Kong fund, and runs the web demo plus an outbox worker; the worker exposes
its own health endpoint on 8770. Stop it with `Ctrl+C`. Sandbox identities are
bound to loopback; the runtime refuses a non-loopback bind unless you opt in
explicitly, and production profiles reject that opt-in outright.

To run the full test suite against a local database:

```sh
DATABASE_URL=postgresql://user@127.0.0.1:5432/rwa node scripts/migrate.js
DATABASE_URL=postgresql://user@127.0.0.1:5432/rwa node --test --test-concurrency=1
```

## What it enforces

| Guarantee | How it is enforced |
|---|---|
| Investor eligibility, holding limits, NAV freshness, price deviation | Checked inside the settlement transaction, re-checked at authorize and accept |
| Maker/checker on product activation, exception handling, ZK parameters | Database constraints — the same principal cannot approve their own request |
| Append-only audit, receipts, spent nullifiers, state history | Triggers; the runtime role has no `DELETE`, `TRUNCATE` or `TRIGGER` rights |
| Migration vs runtime separation | Production startup fails closed if the runtime identity owns the schema |
| Tamper-evident history | Tenant-wide audit checkpoints fold every event into a rolling digest for external anchoring |
| Confidential transfers | Groth16 JoinSplit with server-side recipient eligibility and a registered owner key |
| Institution callbacks | Verified against governed signing keys; revocation takes effect immediately |
| Delivery ordering | Outbox events of one aggregate are delivered strictly in enqueue order |

## Verified, not asserted

- **190 tests, 0 failures** against PostgreSQL 16, including concurrency,
  serialization-failure retries, connection kills and restart recovery.
- An **independent architecture and security review** (2026-09-11) produced 4
  high, 6 medium and 7 low findings. Every one is either fixed or documented
  with its reason: [remediation record](docs/SECURITY_REMEDIATION_2026-09-11.md).
  Two of them were reproduced by a failing test before being fixed.
- Circuit evidence is reproducible: `npm run zk:fixture-provenance` states what
  the stored Groth16 vector proves, and — deliberately — what it does not.

## Architecture in one paragraph

Three processes share one PostgreSQL instance: the web service, an outbox
worker, and an isolated prover worker. A confidential transfer is prepared by a
distributor (naming both parties' credentials), its 13 public signals are frozen
at authorize, a proof is accepted (spending nullifiers), then two operators
propose and approve the new note-tree root — which the server recomputes from a
Poseidon Merkle frontier rather than trusting what was submitted. Everything
else — subscriptions, transfers, redemptions — runs through a durable workflow
with idempotency, evidence envelopes and an append-only ledger.

## Scope and limits

This repository is a working domain kernel, not a licensed financial product.
Honest boundaries, stated up front:

- **Synthetic data only.** No real assets, investors or institutions.
- **The candidate circuit is not audited** and has no production ceremony. The
  stored verification key's circuit source is asserted by the operator, not
  proven — see [zk-candidate/NOT_APPROVED.md](zk-candidate/NOT_APPROVED.md).
- **External dependencies remain external:** production KMS/HSM, an identity
  provider, institution connectors, the legal register bridge, authoritative
  root publication, licensing and legal opinions.
- Audit checkpoints only prove anything once published to an external anchor.
- Institution IDs are global rather than tenant-scoped (accepted, documented).

## Documentation

- [Demo guide](docs/DEMO_GUIDE.md) — the 12-step walkthrough
- [Confidential settlement API](docs/CONFIDENTIAL_SETTLEMENT_API.md)
- [Audit chain anchoring](docs/AUDIT_CHAIN_ANCHORING.md)
- [Production deployment](docs/PRODUCTION_DEPLOYMENT.md) — fail-closed profile
- [Connector conformance](docs/CONNECTOR_CONFORMANCE.md) — institution callbacks
- [Outbox operations](docs/OUTBOX_OPERATIONS.md) · [Prover operations](docs/PROVER_OPERATIONS.md) · [Resilience testing](docs/RESILIENCE_TESTING.md)
- [Product boundary](docs/PRODUCT_COMPLETION.md) — what is and is not built
- [Security remediation record](docs/SECURITY_REMEDIATION_2026-09-11.md)

## Contributing and security

Issues and pull requests are welcome. Please report vulnerabilities privately —
see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
