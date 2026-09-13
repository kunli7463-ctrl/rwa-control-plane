# Independent audit remediation — 2026-09-01

## Scope and current decision

This remediation addresses the independently reported activation-evidence
signature bypass and the unsafe ambiguity between the synthetic Demo runtime
and a production runtime. It does not authorize real-asset use. External KMS,
OIDC/IGA, message infrastructure, institution connectors, audited ZK artifacts,
deployment controls and legal approval remain deployment prerequisites.

## Completed code changes

1. Product activation evidence now uses a versioned canonical payload and real
   Ed25519 verification. The signature binds tenant, product, evidence,
   requirement, source institution, schema, content hash, issue/expiry time,
   algorithm and key ID.
2. Institution signing keys have explicit algorithm, lifecycle, validity,
   revocation and immutable verification metadata. Revocation fails dependent
   activation state closed.
3. Negative tests cover forged signatures, wrong keys, every canonical context
   mutation, unknown/revoked keys, expiry and cross-tenant replay.
4. `NODE_ENV=production` can no longer silently start Sandbox defaults.
   `DEPLOYMENT_PROFILE=production` requires PostgreSQL, OIDC, exact HTTPS/TLS,
   a non-Sandbox tenant and KMS; raw/local keys are rejected.
5. Production startup verifies but never applies migrations and never creates
   synthetic Demo data. Demo actions and reset are disabled.
6. Production payload encryption uses an injected KMS envelope provider.
   Economic commitments use a KMS `generateMac` interface rather than a local
   HMAC master key.
7. Production Outbox refuses the simulated consumer and requires an external
   publisher module. Delivery remains explicitly at-least-once and recipients
   must deduplicate by event ID.

## Verification performed here

Command:

```sh
node --test --test-concurrency=1
```

Result: 125 tests discovered; 110 passed; 0 failed; 15 PostgreSQL integration
tests skipped because the Codex macOS sandbox denies the PostgreSQL shared
memory operation. Real Groth16 positive and negative vectors passed in this run.

## Required Warp verification

Run outside the Codex sandbox:

```sh
cd <repo>
./scripts/final-acceptance.sh
```

Acceptance requires zero failures and zero skips, including migration 021,
activation-signature database tests, PostgreSQL atomicity and Groth16 database
vectors. Record the terminal result before changing the project status.

## Items deliberately not claimed complete

- No real cloud KMS/HSM provider or workload identity is bundled.
- No real OIDC tenant, immutable person ID or IGA separation has been tested.
- No real bank, custodian, registrar, NAV or message-broker endpoint is connected.
- No end-to-end exactly-once guarantee is claimed.
- No Kubernetes/systemd production contract, WAF, backup restore, failover,
  penetration test or independent circuit audit is completed by this change.
