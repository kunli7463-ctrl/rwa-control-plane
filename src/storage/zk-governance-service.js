import { randomUUID } from "node:crypto";
import { JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, normalizeFieldElement } from "../security/proof-adapter.js";
import { emptyMerkleTreeState } from "../security/poseidon-merkle.js";
import { sha256Canonical } from "./postgres-store.js";

// M5: governed changes to the confidential rail's trust parameters.
//
// CIRCUIT_ACTIVATION can only activate the artifact this runtime has pinned
// and loaded (same verification-key and manifest hashes), so an approval can
// never point production at an unreviewed key. PRODUCT_CONTEXT binds a fresh
// contextId and assetType to a product and, in the same transaction, creates
// the empty genesis note tree with its frontier. Importing an existing tree
// is deliberately unsupported: notes carried into a new context would get new
// nullifiers and could be spent twice.

function governanceError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function bounded(value, label, max = 200) {
  if (typeof value !== "string" || value.trim().length < 1 || value.length > max) {
    throw governanceError("INVALID_ZK_PARAMETER_PROPOSAL", `${label} must be a bounded non-empty string`);
  }
  return value;
}

export class ZkGovernanceService {
  constructor(store, { proofAdapter, tenantId }) {
    if (!proofAdapter || proofAdapter.mode !== "GROTH16_VERIFIED") {
      throw governanceError("PRODUCTION_PROOF_ADAPTER_REQUIRED", "ZK governance requires the pinned Groth16 adapter");
    }
    Object.assign(this, { store, proofAdapter, tenantId: bounded(tenantId, "tenantId") });
  }

  async propose({ tenantId, kind, input, proposedBy }) {
    if (tenantId !== this.tenantId) throw governanceError("TENANT_SCOPE_MISMATCH", "proposal is outside this runtime tenant");
    bounded(proposedBy, "proposedBy");
    const payload = kind === "CIRCUIT_ACTIVATION" ? this.#circuitPayload()
      : kind === "PRODUCT_CONTEXT" ? this.#contextPayload(input)
        : (() => { throw governanceError("INVALID_ZK_PARAMETER_PROPOSAL", "unsupported ZK parameter proposal kind"); })();
    return this.store.withSerializableTransaction(async (client) => {
      if (kind === "PRODUCT_CONTEXT") await this.#assertContextAvailable(client, payload);
      else await this.#assertCircuitAvailable(client, payload);
      const pending = await client.query(
        `SELECT 1 FROM rwa.zk_parameter_proposals WHERE tenant_id=$1 AND status='PENDING' AND kind=$2
           AND (kind<>'PRODUCT_CONTEXT' OR payload->>'productId'=$3) FOR UPDATE`,
        [tenantId, kind, payload.productId ?? ""],
      );
      if (pending.rowCount) throw governanceError("ZK_PARAMETER_PROPOSAL_PENDING", "an equivalent proposal is already pending");
      const id = `zk-parameters:${randomUUID()}`;
      const payloadHash = sha256Canonical(payload);
      await client.query(
        `INSERT INTO rwa.zk_parameter_proposals(id,tenant_id,kind,payload,payload_hash,status,proposed_by)
         VALUES ($1,$2,$3,$4::jsonb,$5,'PENDING',$6)`,
        [id, tenantId, kind, JSON.stringify(payload), payloadHash, proposedBy],
      );
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.parameters.proposed", aggregateType: "zk_parameters", aggregateId: id,
        metadata: { proposalId: id, kind, payloadHash, proposedBy, ...payload },
      });
      return { proposalId: id, kind, payload, payloadHash, status: "PENDING" };
    });
  }

  async decide({ tenantId, proposalId, decision, reason, decidedBy }) {
    if (tenantId !== this.tenantId) throw governanceError("TENANT_SCOPE_MISMATCH", "proposal is outside this runtime tenant");
    bounded(proposalId, "proposalId");
    bounded(decidedBy, "decidedBy");
    bounded(reason, "reason", 1000);
    if (!["APPROVE", "REJECT"].includes(decision)) throw governanceError("INVALID_ZK_PARAMETER_DECISION", "decision must be APPROVE or REJECT");
    return this.store.withSerializableTransaction(async (client) => {
      const found = await client.query(
        "SELECT * FROM rwa.zk_parameter_proposals WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
        [proposalId, tenantId],
      );
      const proposal = found.rows[0];
      if (found.rowCount !== 1 || proposal.status !== "PENDING") {
        throw governanceError("ZK_PARAMETER_PROPOSAL_NOT_PENDING", "proposal is not pending");
      }
      if (proposal.proposed_by === decidedBy) {
        throw governanceError("MAKER_CHECKER_CONFLICT", "ZK parameter maker and checker must differ");
      }
      if (sha256Canonical(proposal.payload) !== proposal.payload_hash) {
        throw governanceError("ZK_PARAMETER_PROPOSAL_INTEGRITY_FAILURE", "stored proposal does not match its digest");
      }
      if (decision === "APPROVE") {
        if (proposal.kind === "CIRCUIT_ACTIVATION") {
          const current = this.#circuitPayload();
          if (sha256Canonical(current) !== proposal.payload_hash) {
            throw governanceError("ZK_ARTIFACT_CHANGED", "the runtime's pinned artifact no longer matches this proposal");
          }
          await this.#assertCircuitAvailable(client, proposal.payload);
          await client.query(
            `INSERT INTO rwa.proof_circuit_versions
             (circuit_id,circuit_version,protocol,curve,verification_key_hash,artifact_manifest_hash,public_signal_order,status,activated_at)
             VALUES ($1,$2,'groth16','bn128',$3,$4,$5::jsonb,'ACTIVE',clock_timestamp())`,
            [proposal.payload.circuitId, proposal.payload.circuitVersion, proposal.payload.verificationKeyHash,
              proposal.payload.artifactManifestHash, JSON.stringify(proposal.payload.publicSignalOrder)],
          );
        } else {
          await this.#assertContextAvailable(client, proposal.payload);
          await client.query(
            `INSERT INTO rwa.zk_product_contexts(product_id,circuit_id,circuit_version,context_id,asset_type,created_by)
             VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6)`,
            [proposal.payload.productId, proposal.payload.circuitId, proposal.payload.circuitVersion,
              proposal.payload.contextId, proposal.payload.assetType, `${proposal.proposed_by}+${decidedBy}`],
          );
          const genesis = emptyMerkleTreeState();
          await client.query(
            `INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,frontier,status,observed_at,source_reference)
             VALUES ($1::numeric,$2::numeric,0,$3::jsonb,'CURRENT',clock_timestamp(),$4)`,
            [proposal.payload.contextId, genesis.root, JSON.stringify(genesis.frontier), `genesis:${proposalId}`],
          );
        }
      }
      const status = decision === "APPROVE" ? "APPROVED" : "REJECTED";
      await client.query(
        `UPDATE rwa.zk_parameter_proposals SET status=$2,decided_by=$3,decided_at=clock_timestamp(),decision_reason=$4 WHERE id=$1`,
        [proposalId, status, decidedBy, reason],
      );
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: `zk.parameters.${status.toLowerCase()}`, aggregateType: "zk_parameters", aggregateId: proposalId,
        metadata: { proposalId, kind: proposal.kind, payloadHash: proposal.payload_hash, maker: proposal.proposed_by,
          checker: decidedBy, reason, ...proposal.payload },
      });
      return { proposalId, kind: proposal.kind, status };
    });
  }

  #circuitPayload() {
    const manifest = this.proofAdapter.manifest;
    return {
      circuitId: manifest.circuitId, circuitVersion: manifest.circuitVersion,
      verificationKeyHash: this.proofAdapter.verificationKeyHash, artifactManifestHash: this.proofAdapter.manifestHash,
      publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER],
    };
  }

  #contextPayload(input) {
    const productId = bounded(input?.productId, "productId");
    let contextId;
    let assetType;
    try {
      contextId = normalizeFieldElement(String(input?.contextId ?? ""), "contextId");
      assetType = normalizeFieldElement(String(input?.assetType ?? ""), "assetType");
    } catch (cause) {
      throw governanceError("INVALID_ZK_PARAMETER_PROPOSAL", cause.message);
    }
    if (contextId === "0" || BigInt(assetType) >= 2n ** 32n) {
      throw governanceError("INVALID_ZK_PARAMETER_PROPOSAL", "contextId must be non-zero and assetType must fit in 32 bits");
    }
    const { circuitId, circuitVersion } = this.proofAdapter.manifest;
    return { productId, contextId, assetType, circuitId, circuitVersion };
  }

  async #assertCircuitAvailable(client, payload) {
    const existing = await client.query(
      "SELECT 1 FROM rwa.proof_circuit_versions WHERE circuit_id=$1 AND circuit_version=$2",
      [payload.circuitId, payload.circuitVersion],
    );
    if (existing.rowCount) throw governanceError("ZK_CIRCUIT_ALREADY_REGISTERED", "this circuit version is already registered");
  }

  async #assertContextAvailable(client, payload) {
    const checks = await client.query(
      `SELECT
         (SELECT status FROM rwa.products p WHERE p.id=$1 AND EXISTS (
            SELECT 1 FROM rwa.ledger_accounts a WHERE a.product_id=p.id AND a.tenant_id=$5)) AS product_status,
         EXISTS (SELECT 1 FROM rwa.zk_product_contexts WHERE product_id=$1 AND retired_at IS NULL) AS has_active_context,
         EXISTS (SELECT 1 FROM rwa.zk_product_contexts WHERE context_id=$2::numeric) AS context_used,
         EXISTS (SELECT 1 FROM rwa.zk_merkle_roots WHERE context_id=$2::numeric) AS roots_exist,
         EXISTS (SELECT 1 FROM rwa.proof_circuit_versions WHERE circuit_id=$3 AND circuit_version=$4 AND status='ACTIVE') AS circuit_active`,
      [payload.productId, payload.contextId, payload.circuitId, payload.circuitVersion, this.tenantId],
    );
    const row = checks.rows[0];
    if (!row.product_status) throw governanceError("UNKNOWN_PRODUCT", "product not found for tenant");
    if (!row.circuit_active) throw governanceError("UNAPPROVED_PROOF_CIRCUIT", "the pinned circuit must be activated first");
    if (row.has_active_context) {
      throw governanceError("ZK_CONTEXT_ALREADY_ACTIVE", "product already has an active context; context rotation requires a note migration design");
    }
    if (row.context_used || row.roots_exist) throw governanceError("ZK_CONTEXT_ID_REUSED", "contextId has been used before and cannot be reused");
  }
}
