import { randomUUID } from "node:crypto";
import {
  JOIN_SPLIT_PUBLIC_SIGNAL_ORDER,
  joinSplitPublicInputsHash,
  normalizeFieldElement,
  normalizeJoinSplitPublicInputs,
} from "../security/proof-adapter.js";

function zkError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

export class ZkSettlementGate {
  constructor(store, { proofAdapter, now = () => new Date(), maxConcurrentVerifications = 2 } = {}) {
    if (!proofAdapter || proofAdapter.mode !== "GROTH16_VERIFIED") {
      throw zkError("PRODUCTION_PROOF_ADAPTER_REQUIRED", "ZK settlement requires a pinned Groth16 adapter");
    }
    this.store = store;
    this.proofAdapter = proofAdapter;
    this.now = now;
    if (!Number.isInteger(maxConcurrentVerifications) || maxConcurrentVerifications < 1 || maxConcurrentVerifications > 32) {
      throw zkError("INVALID_VERIFIER_CONCURRENCY", "verifier concurrency must be an integer between 1 and 32");
    }
    this.maxConcurrentVerifications = maxConcurrentVerifications;
    this.activeVerifications = 0;
  }

  async authorize({ transactionId, tenantId, proofPublicInputs }) {
    this.#assertRequestScope(transactionId, tenantId);
    let normalized;
    try { normalized = normalizeJoinSplitPublicInputs(proofPublicInputs); }
    catch (cause) { throw zkError("INVALID_ZK_AUTHORIZATION", cause.message, cause); }
    if (normalized.inputNullifier0 === normalized.inputNullifier1) {
      throw zkError("INVALID_ZK_AUTHORIZATION", "input nullifiers must be distinct");
    }
    const publicInputsHash = joinSplitPublicInputsHash(normalized);
    return this.store.withSerializableTransaction(async (client) => {
      const transaction = await client.query(
        `SELECT t.tenant_id,t.product_id,t.transaction_type,t.current_state,t.request_hash,t.settlement_rail,
                p.status AS product_status
         FROM rwa.transaction_intents t JOIN rwa.products p ON p.id=t.product_id
         WHERE t.id=$1 FOR UPDATE OF t`,
        [transactionId],
      );
      if (transaction.rowCount !== 1 || transaction.rows[0].tenant_id !== tenantId) {
        throw zkError("UNKNOWN_ZK_TRANSACTION", "transaction is unavailable in this tenant");
      }
      if (transaction.rows[0].current_state !== "PROOF_PENDING") {
        throw zkError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting ZK authorization");
      }
      if (transaction.rows[0].transaction_type !== "TRANSFER") {
        throw zkError("UNSUPPORTED_ZK_TRANSACTION_TYPE", "this JoinSplit gate only authorizes transfers");
      }
      if (transaction.rows[0].settlement_rail !== "CONFIDENTIAL_NOTE") {
        throw zkError("UNSUPPORTED_ZK_SETTLEMENT_RAIL", "transaction is not assigned to the confidential note settlement rail");
      }
      if (transaction.rows[0].product_status !== "ACTIVE") {
        throw zkError("PRODUCT_NOT_ACTIVE", "product is not active for ZK authorization");
      }
      const policy = await client.query(
        `SELECT p.context_id,p.asset_type
         FROM rwa.zk_product_contexts p
         JOIN rwa.proof_circuit_versions c
           ON c.circuit_id=p.circuit_id AND c.circuit_version=p.circuit_version
         WHERE p.product_id=$1 AND p.retired_at IS NULL
           AND p.circuit_id=$2 AND p.circuit_version=$3 AND c.status='ACTIVE'
           AND EXISTS (
             SELECT 1 FROM rwa.ledger_accounts a
             WHERE a.product_id=p.product_id AND a.tenant_id=$4
           )
         FOR SHARE OF p,c`,
        [transaction.rows[0].product_id, this.proofAdapter.manifest.circuitId,
          this.proofAdapter.manifest.circuitVersion, tenantId],
      );
      if (policy.rowCount !== 1) throw zkError("UNAPPROVED_PROOF_CONTEXT", "product has no active context for this proof circuit");
      const instruction = await client.query(
        `SELECT tenant_id,request_hash,fee,recipient,relayer,authorized_by,expires_at
         FROM rwa.zk_execution_instructions WHERE transaction_id=$1 FOR SHARE`,
        [transactionId],
      );
      if (instruction.rowCount !== 1
          || instruction.rows[0].tenant_id !== tenantId
          || instruction.rows[0].request_hash !== transaction.rows[0].request_hash) {
        throw zkError("INVALID_ZK_EXECUTION_INSTRUCTION", "transaction has no matching immutable execution instruction");
      }
      if (instruction.rows[0].expires_at <= this.now()) {
        throw zkError("ZK_EXECUTION_INSTRUCTION_EXPIRED", "execution instruction has expired");
      }
      const serverOwned = {
        contextId: policy.rows[0].context_id,
        assetType: policy.rows[0].asset_type,
        fee: instruction.rows[0].fee,
        recipient: instruction.rows[0].recipient,
        relayer: instruction.rows[0].relayer,
      };
      for (const [name, value] of Object.entries(serverOwned)) {
        if (normalized[name] !== value) {
          throw zkError("ZK_BUSINESS_CONTEXT_MISMATCH", `${name} does not match the server-authorized execution context`);
        }
      }
      const root = await client.query(
        `SELECT status,expires_at FROM rwa.zk_merkle_roots
         WHERE context_id=$1::numeric AND merkle_root=$2::numeric FOR SHARE`,
        [normalized.contextId, normalized.merkleRoot],
      );
      if (root.rowCount !== 1 || root.rows[0].status === "REVOKED"
          || (root.rows[0].expires_at && root.rows[0].expires_at <= this.now())) {
        throw zkError("UNACCEPTED_MERKLE_ROOT", "Merkle root is unknown, revoked or expired");
      }
      try {
        await client.query(
          `INSERT INTO rwa.zk_transaction_authorizations
           (transaction_id,tenant_id,circuit_id,circuit_version,merkle_root,context_id,asset_type,fee,
            recipient,relayer,transaction_hash,input_nullifier_0,input_nullifier_1,
            output_commitment_x_0,output_commitment_x_1,output_commitment_y_0,output_commitment_y_1,
            public_inputs_hash,authorized_by)
           VALUES ($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8::numeric,$9::numeric,$10::numeric,
             $11::numeric,$12::numeric,$13::numeric,$14::numeric,$15::numeric,$16::numeric,$17::numeric,$18,$19)`,
          [transactionId, tenantId, this.proofAdapter.manifest.circuitId, this.proofAdapter.manifest.circuitVersion,
            normalized.merkleRoot, normalized.contextId, normalized.assetType, normalized.fee,
            normalized.recipient, normalized.relayer, normalized.transactionHash, normalized.inputNullifier0,
            normalized.inputNullifier1, normalized.outputCommitmentX0, normalized.outputCommitmentX1,
            normalized.outputCommitmentY0, normalized.outputCommitmentY1, publicInputsHash,
            instruction.rows[0].authorized_by],
        );
      } catch (cause) {
        if (cause.code === "23505") throw zkError("ZK_TRANSACTION_ALREADY_AUTHORIZED", "transaction already has immutable ZK inputs", cause);
        throw cause;
      }
      return { transactionId, tenantId, publicInputsHash, status: "PENDING" };
    });
  }

  async accept({ transactionId, tenantId, proof, publicSignals }) {
    this.#assertRequestScope(transactionId, tenantId);
    const authorization = await this.store.pool.query(
      `SELECT a.*,t.current_state AS transaction_state,t.settlement_rail,p.status AS product_status
       FROM rwa.zk_transaction_authorizations a
       JOIN rwa.transaction_intents t ON t.id=a.transaction_id AND t.tenant_id=a.tenant_id
       JOIN rwa.products p ON p.id=t.product_id
       WHERE a.transaction_id=$1 AND a.tenant_id=$2 AND a.status='PENDING'`,
      [transactionId, tenantId],
    );
    if (authorization.rowCount !== 1) {
      throw zkError("ZK_TRANSACTION_NOT_AUTHORIZED", "transaction has no pending immutable ZK authorization");
    }
    const row = authorization.rows[0];
    if (row.transaction_state !== "PROOF_PENDING" || row.settlement_rail !== "CONFIDENTIAL_NOTE") {
      throw zkError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting proof acceptance");
    }
    if (row.product_status !== "ACTIVE") {
      throw zkError("PRODUCT_NOT_ACTIVE", "product is not active for proof acceptance");
    }
    const expectedPublicInputs = {
      merkleRoot: row.merkle_root, contextId: row.context_id, assetType: row.asset_type, fee: row.fee,
      recipient: row.recipient, relayer: row.relayer, transactionHash: row.transaction_hash,
      inputNullifier0: row.input_nullifier_0, inputNullifier1: row.input_nullifier_1,
      outputCommitmentX0: row.output_commitment_x_0, outputCommitmentX1: row.output_commitment_x_1,
      outputCommitmentY0: row.output_commitment_y_0, outputCommitmentY1: row.output_commitment_y_1,
    };
    if (joinSplitPublicInputsHash(expectedPublicInputs) !== row.public_inputs_hash) {
      throw zkError("ZK_AUTHORIZATION_INTEGRITY_FAILURE", "stored ZK authorization does not match its immutable digest");
    }
    if (this.activeVerifications >= this.maxConcurrentVerifications) {
      throw zkError("PROOF_VERIFIER_BUSY", "proof verifier concurrency limit reached");
    }
    this.activeVerifications += 1;
    let verification;
    try {
      verification = await this.proofAdapter.verifyJoinSplit({ proof, publicSignals, expectedPublicInputs });
    } finally {
      this.activeVerifications -= 1;
    }
    return this.store.withSerializableTransaction(async (client) => {
      const transaction = await client.query(
        `SELECT t.tenant_id,t.product_id,t.transaction_type,t.current_state,t.request_hash,t.settlement_rail,
                p.status AS product_status
         FROM rwa.transaction_intents t JOIN rwa.products p ON p.id=t.product_id
         WHERE t.id=$1 FOR UPDATE OF t`,
        [transactionId],
      );
      if (transaction.rowCount !== 1 || transaction.rows[0].tenant_id !== tenantId) {
        throw zkError("UNKNOWN_ZK_TRANSACTION", "transaction is unavailable in this tenant");
      }
      if (transaction.rows[0].current_state !== "PROOF_PENDING") {
        throw zkError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting proof acceptance");
      }
      if (transaction.rows[0].transaction_type !== "TRANSFER") {
        throw zkError("UNSUPPORTED_ZK_TRANSACTION_TYPE", "this JoinSplit gate only accepts transfers");
      }
      if (transaction.rows[0].settlement_rail !== "CONFIDENTIAL_NOTE") {
        throw zkError("UNSUPPORTED_ZK_SETTLEMENT_RAIL", "transaction is not assigned to the confidential note settlement rail");
      }
      if (transaction.rows[0].product_status !== "ACTIVE") {
        throw zkError("PRODUCT_NOT_ACTIVE", "product is not active for proof acceptance");
      }
      const currentContext = await client.query(
        `SELECT 1 FROM rwa.zk_product_contexts
         WHERE product_id=$1 AND circuit_id=$2 AND circuit_version=$3
           AND context_id=$4::numeric AND asset_type=$5::numeric AND retired_at IS NULL
           AND EXISTS (
             SELECT 1 FROM rwa.ledger_accounts a
             WHERE a.product_id=zk_product_contexts.product_id AND a.tenant_id=$6
           )
         FOR SHARE`,
        [transaction.rows[0].product_id, verification.circuitId, verification.circuitVersion,
          expectedPublicInputs.contextId, expectedPublicInputs.assetType, tenantId],
      );
      if (currentContext.rowCount !== 1) {
        throw zkError("ZK_BUSINESS_CONTEXT_RETIRED", "authorized product proof context is no longer active");
      }
      const currentInstruction = await client.query(
        `SELECT 1 FROM rwa.zk_execution_instructions
         WHERE transaction_id=$1 AND tenant_id=$2 AND request_hash=$3
           AND fee=$4::numeric AND recipient=$5::numeric AND relayer=$6::numeric
           AND expires_at>$7
         FOR SHARE`,
        [transactionId, tenantId, transaction.rows[0].request_hash, expectedPublicInputs.fee,
          expectedPublicInputs.recipient, expectedPublicInputs.relayer, this.now()],
      );
      if (currentInstruction.rowCount !== 1) {
        throw zkError("INVALID_ZK_EXECUTION_INSTRUCTION", "authorized execution instruction no longer matches the transaction");
      }
      const circuit = await client.query(
        `SELECT verification_key_hash,artifact_manifest_hash,public_signal_order
         FROM rwa.proof_circuit_versions
         WHERE circuit_id=$1 AND circuit_version=$2 AND status='ACTIVE' FOR SHARE`,
        [verification.circuitId, verification.circuitVersion],
      );
      if (circuit.rowCount !== 1
          || circuit.rows[0].verification_key_hash !== verification.verificationKeyHash
          || circuit.rows[0].artifact_manifest_hash !== verification.manifestHash
          || JSON.stringify(circuit.rows[0].public_signal_order) !== JSON.stringify(this.proofAdapter.manifest.publicSignalOrder)) {
        throw zkError("UNAPPROVED_PROOF_CIRCUIT", "proof circuit artifact is not active and approved");
      }
      const lockedAuthorization = await client.query(
        `SELECT status,public_inputs_hash FROM rwa.zk_transaction_authorizations
         WHERE transaction_id=$1 AND tenant_id=$2 FOR UPDATE`,
        [transactionId, tenantId],
      );
      if (lockedAuthorization.rowCount !== 1 || lockedAuthorization.rows[0].status !== "PENDING") {
        throw zkError("ZK_TRANSACTION_NOT_AUTHORIZED", "ZK authorization was already consumed or revoked");
      }
      const contextId = expectedPublicInputs.contextId;
      const merkleRoot = expectedPublicInputs.merkleRoot;
      const root = await client.query(
        `SELECT status,expires_at FROM rwa.zk_merkle_roots
         WHERE context_id=$1::numeric AND merkle_root=$2::numeric FOR SHARE`,
        [contextId, merkleRoot],
      );
      if (root.rowCount !== 1 || root.rows[0].status === "REVOKED"
          || (root.rows[0].expires_at && root.rows[0].expires_at <= this.now())) {
        throw zkError("UNACCEPTED_MERKLE_ROOT", "Merkle root is unknown, revoked or expired");
      }
      const receiptId = `zk-proof:${transactionId}:${randomUUID()}`;
      await client.query(
        `INSERT INTO rwa.zk_proof_receipts
         (id,transaction_id,tenant_id,circuit_id,circuit_version,context_id,merkle_root,
          verification_key_hash,proof_hash,public_signals_hash,status)
         VALUES ($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10,'VERIFIED')`,
        [receiptId, transactionId, tenantId, verification.circuitId, verification.circuitVersion,
          contextId, merkleRoot, verification.verificationKeyHash, verification.proofHash,
          verification.publicSignalsHash],
      );
      try {
        for (const nullifier of [expectedPublicInputs.inputNullifier0, expectedPublicInputs.inputNullifier1]) {
          await client.query(
            `INSERT INTO rwa.zk_spent_nullifiers(context_id,nullifier,proof_receipt_id)
             VALUES ($1::numeric,$2::numeric,$3)`,
            [contextId, nullifier, receiptId],
          );
        }
      } catch (cause) {
        if (cause.code === "23505") throw zkError("NULLIFIER_ALREADY_SPENT", "proof reuses a spent nullifier", cause);
        throw cause;
      }
      for (const index of [0, 1]) {
        await client.query(
          `INSERT INTO rwa.zk_output_commitments
           (proof_receipt_id,output_index,context_id,commitment_x,commitment_y)
           VALUES ($1,$2,$3::numeric,$4::numeric,$5::numeric)`,
          [receiptId, index, contextId, expectedPublicInputs[`outputCommitmentX${index}`],
            expectedPublicInputs[`outputCommitmentY${index}`]],
        );
      }
      await client.query(
        `UPDATE rwa.zk_transaction_authorizations
         SET status='VERIFIED',proof_receipt_id=$2,verified_at=clock_timestamp()
         WHERE transaction_id=$1`,
        [transactionId, receiptId],
      );
      await this.store.transitionTransaction(client, {
        transactionId,
        toState: "ROOT_PENDING",
        reasonCode: "ZK_JOIN_SPLIT_VERIFIED",
        actorRef: "zk-settlement-gate",
      });
      await client.query(
        `INSERT INTO rwa.zk_settlements
         (transaction_id,proof_receipt_id,tenant_id,product_id,context_id,merkle_root,
          finality_domain,finality_status,legal_register_applied)
         VALUES ($1,$2,$3,$4,$5::numeric,$6::numeric,'CONFIDENTIAL_PROOF_REGISTRY','ROOT_PENDING',false)`,
        [transactionId, receiptId, tenantId, transaction.rows[0].product_id, contextId, merkleRoot],
      );
      const transactionReceipt = {
        transactionId,
        productId: transaction.rows[0].product_id,
        type: "TRANSFER",
        state: "ROOT_PENDING",
        settledAt: this.now().toISOString(),
        settlementMode: "CONFIDENTIAL_PROOF_REGISTRY",
        finalityDomain: "CONFIDENTIAL_PROOF_REGISTRY",
        legalRegisterApplied: false,
        proofReceiptId: receiptId,
        lifecycle: ["REQUESTED", "POLICY_CHECKED", "PROOF_PENDING", "ROOT_PENDING"],
        proofSystem: "GROTH16_VERIFIED",
      };
      const metadata = {
        receiptId,
        transactionId,
        productId: transaction.rows[0].product_id,
        state: "ROOT_PENDING",
        settlementRail: "CONFIDENTIAL_NOTE",
        circuitId: verification.circuitId,
        circuitVersion: verification.circuitVersion,
        verificationKeyHash: verification.verificationKeyHash,
        proofHash: verification.proofHash,
        publicSignalsHash: verification.publicSignalsHash,
        finalityDomain: "CONFIDENTIAL_PROOF_REGISTRY",
        rootPublicationRequired: true,
        externalExecutionRequired: true,
        legalRegisterApplied: false,
        provisionalReceipt: transactionReceipt,
      };
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.confidential_transfer.proof_accepted", aggregateType: "transaction",
        aggregateId: transactionId, metadata,
      });
      await this.store.enqueueOutbox(client, {
        tenantId, topic: "rwa.zk.confidential_transfer.root_requested", aggregateId: transactionId, payload: metadata,
      });
      return {
        ...metadata,
        verified: true,
        proofAccepted: true,
        settlementApplied: false,
        transactionState: "ROOT_PENDING",
        finalityDomain: metadata.finalityDomain,
        legalRegisterApplied: metadata.legalRegisterApplied,
      };
    });
  }

  async proposeFinalization({ transactionId, tenantId, outputMerkleRoot, outputTreeSize,
    rootSourceReference, executionReference, proposedBy }) {
    this.#assertRequestScope(transactionId, tenantId);
    let normalizedRoot;
    try { normalizedRoot = normalizeFieldElement(String(outputMerkleRoot ?? ""), "outputMerkleRoot"); }
    catch (cause) { throw zkError("INVALID_ROOT_PUBLICATION", "output Merkle root is not a canonical field element", cause); }
    const treeSize = Number(outputTreeSize);
    for (const [label, value] of Object.entries({ rootSourceReference, executionReference, proposedBy })) {
      if (typeof value !== "string" || value.length < 1 || value.length > 500) {
        throw zkError("INVALID_ROOT_PUBLICATION", `${label} must be a bounded non-empty string`);
      }
    }
    if (!Number.isSafeInteger(treeSize) || treeSize < 2) {
      throw zkError("INVALID_ROOT_PUBLICATION", "output tree size must be a safe integer of at least two");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const pending = await client.query(
        `SELECT t.current_state,t.settlement_rail,p.status AS product_status,r.tree_size AS input_tree_size
         FROM rwa.transaction_intents t
         JOIN rwa.products p ON p.id=t.product_id
         JOIN rwa.zk_settlements z ON z.transaction_id=t.id AND z.finality_status='ROOT_PENDING'
         JOIN rwa.zk_merkle_roots r ON r.context_id=z.context_id AND r.merkle_root=z.merkle_root
         WHERE t.id=$1 AND t.tenant_id=$2 FOR UPDATE OF t,z`,
        [transactionId, tenantId],
      );
      if (pending.rowCount !== 1 || pending.rows[0].current_state !== "ROOT_PENDING"
          || pending.rows[0].settlement_rail !== "CONFIDENTIAL_NOTE") {
        throw zkError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting authoritative root finality");
      }
      if (pending.rows[0].product_status !== "ACTIVE") {
        throw zkError("PRODUCT_NOT_ACTIVE", "product is not active for root finality");
      }
      if (treeSize < Number(pending.rows[0].input_tree_size) + 2) {
        throw zkError("INVALID_ROOT_PUBLICATION", "published tree size cannot contain both verified outputs");
      }
      const proposalId = `zk-finality:${transactionId}:${randomUUID()}`;
      try {
        await client.query(
          `INSERT INTO rwa.zk_finalization_proposals
           (id,transaction_id,tenant_id,output_merkle_root,output_tree_size,root_source_reference,
            execution_reference,status,proposed_by)
           VALUES ($1,$2,$3,$4::numeric,$5,$6,$7,'PENDING',$8)`,
          [proposalId, transactionId, tenantId, normalizedRoot, treeSize, rootSourceReference,
            executionReference, proposedBy],
        );
      } catch (cause) {
        if (cause.code === "23505") throw zkError("ROOT_FINALIZATION_ALREADY_PROPOSED", "transaction already has a finalization proposal", cause);
        throw cause;
      }
      const metadata = { proposalId, transactionId, outputMerkleRoot: normalizedRoot,
        outputTreeSize: treeSize, rootSourceReference, executionReference, proposedBy, status: "PENDING" };
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.confidential_transfer.finality_proposed",
        aggregateType: "transaction", aggregateId: transactionId, metadata,
      });
      await this.store.enqueueOutbox(client, {
        tenantId, topic: "rwa.zk.confidential_transfer.finality_proposed",
        aggregateId: transactionId, payload: metadata,
      });
      return metadata;
    });
  }

  async finalize({ transactionId, tenantId, finalizedBy }) {
    this.#assertRequestScope(transactionId, tenantId);
    if (typeof finalizedBy !== "string" || finalizedBy.length < 1 || finalizedBy.length > 500) {
      throw zkError("INVALID_ROOT_PUBLICATION", "finalizedBy must be a bounded non-empty string");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const current = await client.query(
        `SELECT t.product_id,t.current_state,t.settlement_rail,p.status AS product_status,
                z.proof_receipt_id,z.context_id,z.merkle_root,z.finality_status,
                r.tree_size AS input_tree_size,q.id AS proposal_id,q.output_merkle_root::text,
                q.output_tree_size,q.root_source_reference,q.execution_reference,q.proposed_by
         FROM rwa.transaction_intents t
         JOIN rwa.products p ON p.id=t.product_id
         JOIN rwa.zk_settlements z ON z.transaction_id=t.id
         JOIN rwa.zk_merkle_roots r ON r.context_id=z.context_id AND r.merkle_root=z.merkle_root
         JOIN rwa.zk_finalization_proposals q ON q.transaction_id=t.id AND q.tenant_id=t.tenant_id
           AND q.status='PENDING'
         WHERE t.id=$1 AND t.tenant_id=$2 FOR UPDATE OF t,z,q`,
        [transactionId, tenantId],
      );
      if (current.rowCount !== 1) throw zkError("UNKNOWN_ZK_TRANSACTION", "root-pending transaction is unavailable in this tenant");
      const row = current.rows[0];
      if (row.current_state !== "ROOT_PENDING" || row.settlement_rail !== "CONFIDENTIAL_NOTE"
          || row.finality_status !== "ROOT_PENDING") {
        throw zkError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting authoritative root finality");
      }
      if (row.product_status !== "ACTIVE") throw zkError("PRODUCT_NOT_ACTIVE", "product is not active for root finality");
      if (row.proposed_by === finalizedBy) {
        throw zkError("MAKER_CHECKER_SEPARATION_REQUIRED", "finality proposer cannot approve the same transaction");
      }
      const normalizedRoot = row.output_merkle_root;
      const treeSize = Number(row.output_tree_size);
      const rootSourceReference = row.root_source_reference;
      const executionReference = row.execution_reference;
      if (treeSize < Number(row.input_tree_size) + 2) {
        throw zkError("INVALID_ROOT_PUBLICATION", "published tree size cannot contain both verified outputs");
      }
      const activeRoot = await client.query(
        `SELECT merkle_root::text,tree_size FROM rwa.zk_merkle_roots
         WHERE context_id=$1::numeric AND status='CURRENT' FOR UPDATE`,
        [row.context_id],
      );
      if (activeRoot.rowCount === 1 && activeRoot.rows[0].merkle_root !== normalizedRoot) {
        if (treeSize <= Number(activeRoot.rows[0].tree_size)) {
          throw zkError("STALE_ROOT_PUBLICATION", "published root does not advance the current tree");
        }
        await client.query(
          `UPDATE rwa.zk_merkle_roots SET status='HISTORICAL',expires_at=clock_timestamp()+interval '1 hour'
           WHERE context_id=$1::numeric AND status='CURRENT'`, [row.context_id],
        );
      }
      if (activeRoot.rowCount === 0 || activeRoot.rows[0].merkle_root !== normalizedRoot) {
        await client.query(
          `INSERT INTO rwa.zk_merkle_roots
           (context_id,merkle_root,tree_size,status,observed_at,source_reference)
           VALUES ($1::numeric,$2::numeric,$3,'CURRENT',clock_timestamp(),$4)`,
          [row.context_id, normalizedRoot, treeSize, rootSourceReference],
        );
      } else if (Number(activeRoot.rows[0].tree_size) !== treeSize) {
        throw zkError("ROOT_PUBLICATION_CONFLICT", "published root already exists with a different tree size");
      }
      await client.query(
        `UPDATE rwa.zk_finalization_proposals
         SET status='APPROVED',approved_by=$2,approved_at=clock_timestamp()
         WHERE id=$1`, [row.proposal_id, finalizedBy],
      );
      await client.query(
        `INSERT INTO rwa.zk_root_publication_attestations
         (transaction_id,tenant_id,context_id,proof_receipt_id,output_merkle_root,output_tree_size,
          root_source_reference,execution_reference,attested_by,proposal_id,approved_by)
         VALUES ($1,$2,$3::numeric,$4,$5::numeric,$6,$7,$8,$9,$10,$11)`,
        [transactionId, tenantId, row.context_id, row.proof_receipt_id, normalizedRoot, treeSize,
          rootSourceReference, executionReference, row.proposed_by, row.proposal_id, finalizedBy],
      );
      await client.query(
        `UPDATE rwa.zk_settlements SET finality_domain='CONFIDENTIAL_NOTE_LEDGER',finality_status='FINAL',
           output_merkle_root=$2::numeric,output_tree_size=$3,root_source_reference=$4,
           execution_reference=$5,finalized_by=$6,finalized_at=clock_timestamp()
         WHERE transaction_id=$1`,
        [transactionId, normalizedRoot, treeSize, rootSourceReference, executionReference, finalizedBy],
      );
      await this.store.transitionTransaction(client, {
        transactionId, toState: "SETTLED", reasonCode: "ZK_ROOT_AND_EFFECTS_ATTESTED", actorRef: finalizedBy,
      });
      const metadata = {
        transactionId, productId: row.product_id, state: "SETTLED",
        proofReceiptId: row.proof_receipt_id, inputMerkleRoot: row.merkle_root,
        outputMerkleRoot: normalizedRoot, outputTreeSize: treeSize,
        rootSourceReference, executionReference,
        finalityDomain: "CONFIDENTIAL_NOTE_LEDGER", legalRegisterApplied: false,
      };
      const transactionReceiptHash = await this.store.storeReceipt(client, {
        transactionId, receipt: { ...metadata, type: "TRANSFER", settledAt: this.now().toISOString(),
          lifecycle: ["REQUESTED", "POLICY_CHECKED", "PROOF_PENDING", "ROOT_PENDING", "SETTLED"] },
      });
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.confidential_transfer.settled", aggregateType: "transaction",
        aggregateId: transactionId, metadata: { ...metadata, transactionReceiptHash },
      });
      await this.store.enqueueOutbox(client, {
        tenantId, topic: "rwa.zk.confidential_transfer.settled", aggregateId: transactionId,
        payload: { ...metadata, transactionReceiptHash },
      });
      return { ...metadata, transactionReceiptHash, proofAccepted: true,
        rootPublicationAttested: true, externalExecutionAttested: true,
        maker: row.proposed_by, checker: finalizedBy, settlementApplied: true };
    });
  }

  #assertRequestScope(transactionId, tenantId) {
    if (typeof transactionId !== "string" || transactionId.length < 1 || transactionId.length > 200
        || typeof tenantId !== "string" || tenantId.length < 1 || tenantId.length > 200) {
      throw zkError("INVALID_ZK_REQUEST_SCOPE", "bounded transaction and tenant identifiers are required");
    }
  }
}
