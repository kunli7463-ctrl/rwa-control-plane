import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ELIGIBLE_RULES_JSON } from "../helpers/confidential-parties.js";
import { emptyMerkleTreeState } from "../../src/security/poseidon-merkle.js";
import { Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, verificationKeyHash } from "../../src/security/proof-adapter.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ZkGovernanceService } from "../../src/storage/zk-governance-service.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("circuit activation and product contexts are maker/checker governed and start from a verifiable genesis", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 2 });
  await runMigrations(store.pool, { migrationsDir: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations") });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `gov-${suffix}`;
  const productId = `gov-product-${suffix}`;
  const verificationKey = { protocol: "groth16", curve: "bn128", id: suffix };
  const manifest = { protocol: "groth16", curve: "bn128", circuitId: `gov-${suffix}`, circuitVersion: "1.0.0",
    publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER] };
  const proofAdapter = new Groth16JoinSplitProofAdapter({ verifier: { verify: async () => true }, verificationKey, manifest,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey) });
  const governance = new ZkGovernanceService(store, { proofAdapter, tenantId });
  const query = (sql, values) => store.pool.query(sql, values);
  const contextId = (BigInt(Date.now()) * 1000n + 7n).toString();
  try {
    await query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'G','HK','ACTIVE','test')", [`gov-issuer-${suffix}`]);
    await query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'G','HK',$2,'HKD','ACTIVE',1,$3::jsonb)",
      [productId, `gov-issuer-${suffix}`, ELIGIBLE_RULES_JSON]);
    await query(`INSERT INTO rwa.ledger_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ($1,$2,$3,'owner',$4,'INVESTOR')`, [`gov-ledger-${suffix}`, tenantId, productId, `UNIT:${productId}`]);

    await assert.rejects(governance.propose({ tenantId, kind: "PRODUCT_CONTEXT", proposedBy: "maker",
      input: { productId, contextId, assetType: "7" } }), { code: "UNAPPROVED_PROOF_CIRCUIT" });
    const circuit = await governance.propose({ tenantId, kind: "CIRCUIT_ACTIVATION", proposedBy: "maker" });
    assert.equal(circuit.payload.verificationKeyHash, proofAdapter.verificationKeyHash);
    await assert.rejects(governance.propose({ tenantId, kind: "CIRCUIT_ACTIVATION", proposedBy: "maker" }),
      { code: "ZK_PARAMETER_PROPOSAL_PENDING" });
    await assert.rejects(governance.decide({ tenantId, proposalId: circuit.proposalId, decision: "APPROVE",
      reason: "self approval", decidedBy: "maker" }), { code: "MAKER_CHECKER_CONFLICT" });
    assert.equal((await governance.decide({ tenantId, proposalId: circuit.proposalId, decision: "APPROVE",
      reason: "artifact reviewed", decidedBy: "checker" })).status, "APPROVED");

    await assert.rejects(governance.propose({ tenantId, kind: "PRODUCT_CONTEXT", proposedBy: "maker",
      input: { productId, contextId, assetType: String(2n ** 32n) } }), { code: "INVALID_ZK_PARAMETER_PROPOSAL" });
    const rejected = await governance.propose({ tenantId, kind: "PRODUCT_CONTEXT", proposedBy: "maker",
      input: { productId, contextId, assetType: "7" } });
    await governance.decide({ tenantId, proposalId: rejected.proposalId, decision: "REJECT", reason: "wrong asset", decidedBy: "checker" });
    const context = await governance.propose({ tenantId, kind: "PRODUCT_CONTEXT", proposedBy: "maker",
      input: { productId, contextId, assetType: "8" } });
    await governance.decide({ tenantId, proposalId: context.proposalId, decision: "APPROVE", reason: "asset type confirmed", decidedBy: "checker" });
    const state = await query(
      `SELECT c.asset_type::text,r.merkle_root::text,r.tree_size,r.status,jsonb_array_length(r.frontier) AS levels
       FROM rwa.zk_product_contexts c JOIN rwa.zk_merkle_roots r ON r.context_id=c.context_id WHERE c.product_id=$1`,
      [productId],
    );
    assert.deepEqual(state.rows, [{ asset_type: "8", merkle_root: emptyMerkleTreeState().root, tree_size: "0", status: "CURRENT", levels: 32 }]);
    await assert.rejects(governance.propose({ tenantId, kind: "PRODUCT_CONTEXT", proposedBy: "maker",
      input: { productId, contextId: (BigInt(contextId) + 1n).toString(), assetType: "8" } }), { code: "ZK_CONTEXT_ALREADY_ACTIVE" });
    await assert.rejects(governance.decide({ tenantId, proposalId: context.proposalId, decision: "APPROVE",
      reason: "again", decidedBy: "checker" }), { code: "ZK_PARAMETER_PROPOSAL_NOT_PENDING" });
    const audit = await query(
      "SELECT count(*)::int AS count FROM rwa.audit_events WHERE tenant_id=$1 AND aggregate_type='zk_parameters'",
      [tenantId],
    );
    assert.equal(audit.rows[0].count, 6);
  } finally {
    await store.close();
  }
});
