import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createDemoScenario, DEMO_PRODUCT_ID } from "./seed.js";
import { AesGcmEnvelopeCipher, KmsEnvelopeCipher, LocalKeyring } from "./security/envelope-crypto.js";
import {
  deriveEconomicCommitmentKey, EconomicCommitter, KmsEconomicCommitter,
} from "./security/economic-commitment.js";
import { loadPinnedGroth16Adapter } from "./security/snarkjs-verifier.js";
import { IsolatedProverClient } from "./security/isolated-prover-client.js";
import { DurableWorkflowService } from "./storage/durable-workflow-service.js";
import { ConfidentialTransferService } from "./storage/confidential-transfer-service.js";
import { runMigrations, verifyMigrations } from "./storage/migrate.js";
import { verifyRuntimeDatabasePrivileges } from "./storage/database-privileges.js";
import { PostgresReadModel } from "./storage/postgres-read-model.js";
import { PostgresStore } from "./storage/postgres-store.js";
import { ZkSettlementGate } from "./storage/zk-settlement-gate.js";
import { ZkGovernanceService } from "./storage/zk-governance-service.js";
import { ProverJobService } from "./storage/prover-job-service.js";
import { InstitutionCallbackService } from "./storage/institution-callback-service.js";
import { ProductCatalogService } from "./storage/product-catalog-service.js";
import { MemoryWorkflowAdapter, PostgresWorkflowAdapter } from "./workflow-adapters.js";
import { loadKmsProvider, resolveEncryptionKey } from "./runtime-config.js";

const MEMORY_CAPABILITIES = Object.freeze({
  subscribe: true,
  transfer: true,
  redeem: true,
  "revoke-b": true,
  "simulate-register-failure": true,
  "propose-exception-retry": true,
  "approve-exception-retry": true,
  pause: true,
  resume: true,
  reset: true,
});

const POSTGRES_CAPABILITIES = Object.freeze({
  subscribe: true,
  transfer: true,
  redeem: true,
  "revoke-b": true,
  "simulate-register-failure": true,
  "propose-exception-retry": true,
  "approve-exception-retry": true,
  pause: true,
  resume: true,
  reset: false,
});

const PRODUCTION_CAPABILITIES = Object.freeze({
  subscribe: false,
  transfer: false,
  redeem: false,
  "revoke-b": false,
  "simulate-register-failure": false,
  "propose-exception-retry": false,
  "approve-exception-retry": false,
  pause: false,
  resume: false,
  reset: false,
});

function runtimeError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

async function ensurePostgresSeed(store, service, scenario) {
  const existing = await store.pool.query(
    `SELECT p.id,p.issuer_id,p.currency,p.jurisdiction,
            (SELECT count(*)::int FROM rwa.product_role_assignments r WHERE r.product_id=p.id AND r.ended_at IS NULL) AS role_count,
            (SELECT count(*)::int FROM rwa.credentials c WHERE c.product_id=p.id) AS credential_count,
            (SELECT count(*)::int FROM rwa.evidence_envelopes e WHERE e.product_id=p.id AND e.data_type='nav') AS nav_count,
            (SELECT count(*)::int FROM rwa.ledger_accounts a WHERE a.product_id=p.id AND a.tenant_id='sandbox-hk') AS account_count
     FROM rwa.products p WHERE p.id=$1`,
    [DEMO_PRODUCT_ID],
  );
  if (existing.rowCount === 0) {
    await service.bootstrapFromControlPlane(scenario.plane);
    await ensureDemoCatalogBindings(store);
    return "CREATED";
  }
  const row = existing.rows[0];
  const valid = row.issuer_id === "demo-issuer"
    && row.currency === "HKD"
    && row.jurisdiction === "HK"
    && row.role_count === 7
    && row.credential_count >= 2
    && row.nav_count >= 1
    && row.account_count >= 1;
  if (!valid) {
    throw runtimeError("INCOMPLETE_EXISTING_BOOTSTRAP", "existing PostgreSQL demo product is incomplete or belongs to a different configuration");
  }
  await ensureDemoCatalogBindings(store);
  return "VERIFIED_EXISTING";
}

async function ensureDemoCatalogBindings(store) {
  await store.withSerializableTransaction(async (client) => {
    await client.query(
      `INSERT INTO rwa.tenant_institutions(tenant_id,institution_id,onboarding_status)
       SELECT 'sandbox-hk',i.id,'APPROVED' FROM rwa.institutions i WHERE i.id LIKE 'demo-%'
       ON CONFLICT (tenant_id,institution_id) DO NOTHING`,
    );
    await client.query(
      `INSERT INTO rwa.product_configurations
       (product_id,tenant_id,template_id,configuration_status,created_by)
       SELECT p.id,'sandbox-hk','FUND_V1','READY_FOR_EVIDENCE','sandbox-seed'
       FROM rwa.products p WHERE p.id=$1
       ON CONFLICT (product_id) DO NOTHING`,
      [DEMO_PRODUCT_ID],
    );
  });
}

export class DemoRuntime {
  constructor({ config, scenario, workflow, readModel = null, store = null, bootstrapState = "NOT_REQUIRED", zkSettlementGate = null, confidentialTransferService = null, proverJobService = null, institutionCallbackService = null, productCatalogService = null, zkGovernanceService = null }) {
    this.config = config;
    this.storageMode = config.storageMode;
    this.scenario = scenario;
    this.workflow = workflow;
    this.readModel = readModel;
    this.store = store;
    this.bootstrapState = bootstrapState;
    this.zkSettlementGate = zkSettlementGate;
    this.confidentialTransferService = confidentialTransferService;
    this.proverJobService = proverJobService;
    this.institutionCallbackService = institutionCallbackService;
    this.productCatalogService = productCatalogService;
    this.zkGovernanceService = zkGovernanceService;
    this.tenantId = config.tenantId;
    this.defaultProductId = config.defaultProductId
      ?? (config.deploymentProfile === "sandbox" ? DEMO_PRODUCT_ID : null);
    this.lastExceptionCaseId = null;
    this.capabilities = {
      ...(config.deploymentProfile === "production"
        ? PRODUCTION_CAPABILITIES
        : (this.storageMode === "postgres" ? POSTGRES_CAPABILITIES : MEMORY_CAPABILITIES)),
      reset: config.deploymentProfile === "sandbox" && config.authMode === "sandbox",
    };
  }

  static async create(config) {
    if (config.deploymentProfile === "sandbox" && config.tenantId !== "sandbox-hk") {
      throw runtimeError(
        "DEMO_RUNTIME_FORBIDDEN",
        "sandbox runtime is restricted to TENANT_ID=sandbox-hk",
      );
    }
    const scenario = config.deploymentProfile === "sandbox" ? createDemoScenario() : null;
    if (config.storageMode === "memory") {
      if (!scenario) throw runtimeError("PRODUCTION_MEMORY_FORBIDDEN", "production runtime cannot use memory storage");
      return new DemoRuntime({ config, scenario, workflow: new MemoryWorkflowAdapter(scenario.plane) });
    }

    const store = await PostgresStore.connect({ connectionString: config.databaseUrl, max: 10 });
    try {
      const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../db/migrations");
      if (config.authMode === "oidc" || config.deploymentProfile === "production") {
        await verifyMigrations(store.pool, { migrationsDir });
        if (config.deploymentProfile === "production") await verifyRuntimeDatabasePrivileges(store.pool);
      } else {
        await runMigrations(store.pool, { migrationsDir });
      }
      let payloadCipher;
      let economicCommitter;
      if (config.envelopeCipherMode === "kms") {
        const kmsProvider = await loadKmsProvider(config);
        payloadCipher = new KmsEnvelopeCipher(kmsProvider);
        economicCommitter = new KmsEconomicCommitter({
          provider: kmsProvider, keyId: config.economicCommitmentKmsKeyId,
        });
      } else {
        const key = await resolveEncryptionKey(config);
        payloadCipher = new AesGcmEnvelopeCipher(new LocalKeyring({
          activeKeyId: config.encryptionKeyId,
          keys: { [config.encryptionKeyId]: key },
        }));
        economicCommitter = new EconomicCommitter({
          key: deriveEconomicCommitmentKey(key), keyId: `${config.encryptionKeyId}:economic-v1`,
        });
      }
      const service = new DurableWorkflowService(store, { tenantId: config.tenantId, payloadCipher, economicCommitter });
      const institutionCallbackService = new InstitutionCallbackService(store, {
        tenantId: config.tenantId, economicCommitter,
      });
      const productCatalogService = new ProductCatalogService(store);
      const bootstrapState = config.deploymentProfile === "sandbox"
        ? await ensurePostgresSeed(store, service, scenario)
        : "PRODUCTION_NO_SEED";
      let zkSettlementGate = null;
      let confidentialTransferService = null;
      let proverJobService = null;
      let zkGovernanceService = null;
      if (config.zkMode === "groth16") {
        const proofAdapter = await loadPinnedGroth16Adapter({
          bundleDirectory: config.zkArtifactDirectory,
          expectedManifestFileHash: config.zkManifestSha256,
        });
        zkSettlementGate = new ZkSettlementGate(store, { proofAdapter });
        zkGovernanceService = new ZkGovernanceService(store, { proofAdapter, tenantId: config.tenantId });
        confidentialTransferService = new ConfidentialTransferService(store, {
          payloadCipher,
          circuitId: proofAdapter.manifest.circuitId,
          circuitVersion: proofAdapter.manifest.circuitVersion,
          tenantId: config.tenantId,
        });
        if (config.proverMode === "isolated") {
          proverJobService = new ProverJobService(store, {
            proverClient: new IsolatedProverClient({
              endpoint: config.proverEndpoint,
              serviceToken: config.proverServiceToken,
              expectedServiceId: config.proverExpectedServiceId,
            }),
            payloadCipher,
            zkSettlementGate,
            tenantId: config.tenantId,
          });
        }
      }
      return new DemoRuntime({
        config,
        scenario,
        workflow: new PostgresWorkflowAdapter(service),
        readModel: new PostgresReadModel(store, { tenantId: config.tenantId, payloadCipher, economicCommitter }),
        store,
        bootstrapState,
        zkSettlementGate,
        confidentialTransferService,
        proverJobService,
        institutionCallbackService,
        productCatalogService,
        zkGovernanceService,
      });
    } catch (error) {
      await store.close();
      throw error;
    }
  }

  async productCatalog(identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product configuration requires PostgreSQL mode");
    }
    return this.productCatalogService.list({ tenantId: identity.tenantId });
  }

  async registerCatalogInstitution(input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product configuration requires PostgreSQL mode");
    }
    return this.productCatalogService.registerInstitution({
      tenantId: identity.tenantId, actorRef: identity.principalId, institution: input,
    });
  }

  async registerCatalogInstitutionSigningKey(institutionId, input, identity) {
    this.#assertTenant(identity);
    this.#assertSigningKeyInstitution(identity, institutionId);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "institution signing-key governance requires PostgreSQL mode");
    }
    return this.productCatalogService.registerInstitutionSigningKey({
      tenantId: identity.tenantId, actorRef: identity.principalId, institutionId, input,
    });
  }

  async revokeCatalogInstitutionSigningKey(institutionId, keyId, input, identity) {
    this.#assertTenant(identity);
    this.#assertSigningKeyInstitution(identity, institutionId);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "institution signing-key governance requires PostgreSQL mode");
    }
    return this.productCatalogService.revokeInstitutionSigningKey({
      tenantId: identity.tenantId, actorRef: identity.principalId,
      institutionId, keyId, reason: input?.reason,
    });
  }

  async createCatalogProduct(input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product configuration requires PostgreSQL mode");
    }
    return this.productCatalogService.createProduct({
      tenantId: identity.tenantId, actorRef: identity.principalId, product: input,
    });
  }

  async assignCatalogProductRole(productId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) {
      throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product configuration requires PostgreSQL mode");
    }
    return this.productCatalogService.assignRole({
      tenantId: identity.tenantId, actorRef: identity.principalId, productId,
      role: input.role, institutionId: input.institutionId,
    });
  }

  async proposeCatalogInstitutionReview(institutionId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.proposeInstitutionReview({
      tenantId: identity.tenantId, actorRef: identity.principalId, institutionId, input,
    });
  }

  async decideCatalogInstitutionReview(institutionId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.decideInstitutionReview({
      tenantId: identity.tenantId, actorRef: identity.principalId, institutionId, input,
    });
  }

  async attachCatalogActivationEvidence(productId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.attachActivationEvidence({
      tenantId: identity.tenantId, actorRef: identity.principalId, productId, input,
    });
  }

  async proposeCatalogActivation(productId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.proposeActivation({
      tenantId: identity.tenantId, actorRef: identity.principalId, productId, input,
    });
  }

  async decideCatalogActivation(productId, input, identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.decideActivation({
      tenantId: identity.tenantId, actorRef: identity.principalId, productId, input,
    });
  }

  async catalogAuditExport(identity) {
    this.#assertTenant(identity);
    if (!this.productCatalogService) throw runtimeError("PRODUCT_CATALOG_REQUIRES_POSTGRES", "product governance requires PostgreSQL mode");
    return this.productCatalogService.auditExport({ tenantId: identity.tenantId });
  }

  async view(identity, productId = this.defaultProductId) {
    this.#assertTenant(identity);
    if (!productId) {
      throw runtimeError("PRODUCT_ID_REQUIRED", "production role view requires an explicit productId");
    }
    const view = this.storageMode === "postgres"
      ? await this.readModel.viewForRole({
        productId, role: identity.role, actorRef: identity.actorRef, institutionId: identity.institutionId,
      })
      : this.scenario.plane.viewForRole({ role: identity.role, actorId: identity.actorRef, productId });
    return {
      ...view,
      runtime: {
        storageMode: this.storageMode === "postgres" ? "POSTGRESQL" : "MEMORY",
        bootstrapState: this.bootstrapState,
        capabilities: { ...this.capabilities },
        zkMode: this.zkSettlementGate ? "GROTH16_VERIFIED" : "DISABLED",
        confidentialTransferApi: Boolean(this.confidentialTransferService && this.zkSettlementGate),
        isolatedProver: Boolean(this.proverJobService),
      },
    };
  }

  async readiness() {
    if (this.storageMode === "memory") {
      return { ready: true, storage: "MEMORY", zk: "DISABLED" };
    }
    await this.store.pool.query("SELECT 1");
    return {
      ready: true,
      storage: "POSTGRESQL",
      zk: this.zkSettlementGate ? "GROTH16_VERIFIED" : "DISABLED",
      confidentialSettlementApi: Boolean(this.confidentialTransferService && this.zkSettlementGate),
      isolatedProver: Boolean(this.proverJobService),
      institutionConnector: Boolean(this.institutionCallbackService),
    };
  }

  async evidencePackage(transactionId, identity) {
    this.#assertTenant(identity);
    if (this.storageMode === "postgres") {
      return this.readModel.transactionEvidencePackage({
        transactionId, role: identity.role, institutionId: identity.institutionId,
      });
    }
    return this.scenario.plane.transactionEvidencePackage(transactionId);
  }

  async runAction(action, identity) {
    this.#assertTenant(identity);
    if (this.config.deploymentProfile !== "sandbox") {
      throw runtimeError("DEMO_ACTION_FORBIDDEN", "synthetic demonstration actions are disabled in production");
    }
    if (!this.capabilities[action]) {
      throw runtimeError("ACTION_UNAVAILABLE_IN_STORAGE_MODE", `${action} is unavailable in ${this.storageMode} mode`);
    }
    const suffix = `${Date.now()}-${randomUUID().slice(0, 8)}`;
    if (action === "subscribe") {
      return this.workflow.subscribe({
        id: `ui-subscribe-${suffix}`,
        idempotencyKey: `ui-subscribe-${suffix}`,
        productId: DEMO_PRODUCT_ID,
        investorId: identity.actorRef,
        credentialId: `credential-${identity.actorRef}`,
        units: "100",
        cashAmount: "1000000",
      });
    }
    if (action === "transfer") {
      return this.workflow.transfer({
        id: `ui-transfer-${suffix}`,
        idempotencyKey: `ui-transfer-${suffix}`,
        productId: DEMO_PRODUCT_ID,
        sellerId: "investor-a",
        sellerCredentialId: "credential-investor-a",
        buyerId: "investor-b",
        buyerCredentialId: "credential-investor-b",
        units: "25",
        pricePerUnit: "10000",
        fee: "100",
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      });
    }
    if (action === "redeem") {
      return this.workflow.redeem({
        id: `ui-redeem-${suffix}`,
        idempotencyKey: `ui-redeem-${suffix}`,
        productId: DEMO_PRODUCT_ID,
        investorId: identity.actorRef,
        credentialId: `credential-${identity.actorRef}`,
        units: "5",
      });
    }

    if (this.storageMode === "postgres") {
      if (action === "reset") {
        const now = new Date();
        const effectiveAt = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
        const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
        const navEvidence = this.scenario.institutions.admin.signStatement({
          id: "nav-demo-001",
          productId: DEMO_PRODUCT_ID,
          dataType: "nav",
          sourceInstitutionId: "demo-admin",
          trustTier: "A",
          effectiveAt,
          expiresAt,
          schemaVersion: "1.0.0",
          payload: { navPerUnit: "10000", currency: "HKD", synthetic: true },
        });
        const reset = await this.workflow.resetSandboxDemo({
          productId: DEMO_PRODUCT_ID,
          actorRef: identity.principalId,
          navEvidence,
        });
        this.lastExceptionCaseId = null;
        return reset;
      }
      if (action === "pause" || action === "resume") {
        return this.workflow.setProductStatus({
          productId: DEMO_PRODUCT_ID,
          status: action === "pause" ? "PAUSED" : "ACTIVE",
          actorRef: identity.principalId,
          reason: "sandbox operator action",
        });
      }
      if (action === "revoke-b") {
        return this.workflow.restrictCredential({
          credentialId: "credential-investor-b",
          actorRef: identity.principalId,
          reason: "sandbox operator action",
        });
      }
      if (action === "simulate-register-failure") {
        const receipt = await this.workflow.simulateRegisterFailure({
          id: `ui-register-failure-${suffix}`,
          productId: DEMO_PRODUCT_ID,
          sellerId: "investor-a",
          sellerCredentialId: "credential-investor-a",
          idempotencyKey: `ui-register-failure-${suffix}`,
          buyerId: "investor-b",
          buyerCredentialId: "credential-investor-b",
          units: "10",
          pricePerUnit: "10000",
          fee: "100",
          expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        });
        this.lastExceptionCaseId = receipt.exceptionCaseId;
        return receipt;
      }
      if (action === "propose-exception-retry") {
        const caseId = this.lastExceptionCaseId ?? await this.#latestExceptionCase("OPEN");
        if (!caseId) throw runtimeError("NO_OPEN_EXCEPTION", "no open exception case");
        const replacementTransactionId = `ui-retry-${suffix}`;
        const result = await this.workflow.proposeExceptionResolution({
          caseId,
          makerId: identity.principalId,
          decision: "RETRY",
          replacementTransactionId,
        });
        this.lastExceptionCaseId = caseId;
        return result;
      }
      if (action === "approve-exception-retry") {
        const caseId = this.lastExceptionCaseId ?? await this.#latestExceptionCase("PENDING_APPROVAL");
        if (!caseId) throw runtimeError("NO_PENDING_EXCEPTION", "no pending exception case");
        const result = await this.workflow.approveExceptionResolution({
          caseId,
          checkerId: identity.principalId,
          decision: "APPROVE",
        });
        if (result.state.startsWith("RESOLVED_")) this.lastExceptionCaseId = null;
        return result;
      }
    }

    const plane = this.scenario.plane;
    if (action === "revoke-b") {
      plane.revokeCredential("credential-investor-b", "sandbox operator action");
      return { state: "RESTRICTED_EXIT", credentialId: "credential-investor-b", permittedAction: "REDEEM_ONLY" };
    }
    if (action === "simulate-register-failure") {
      const receipt = plane.simulateRegisterFailure({
        id: `ui-register-failure-${suffix}`,
        productId: DEMO_PRODUCT_ID,
        sellerId: "investor-a",
        sellerCredentialId: "credential-investor-a",
        idempotencyKey: `ui-register-failure-${suffix}`,
        buyerId: "investor-b",
        buyerCredentialId: "credential-investor-b",
        units: "10",
        pricePerUnit: "10000",
        fee: "100",
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      });
      this.lastExceptionCaseId = receipt.exceptionCaseId;
      return receipt;
    }
    if (action === "propose-exception-retry") {
      if (!this.lastExceptionCaseId) throw runtimeError("NO_OPEN_EXCEPTION", "no open exception case");
      return plane.proposeExceptionResolution({
        caseId: this.lastExceptionCaseId,
        makerId: identity.principalId,
        decision: "RETRY",
        replacementTransactionId: `ui-retry-${suffix}`,
      });
    }
    if (action === "approve-exception-retry") {
      if (!this.lastExceptionCaseId) throw runtimeError("NO_PENDING_EXCEPTION", "no pending exception case");
      return plane.approveExceptionResolution({ caseId: this.lastExceptionCaseId, checkerId: identity.principalId });
    }
    if (action === "pause") {
      plane.pauseProduct(DEMO_PRODUCT_ID, "sandbox operator action");
      return { state: "PAUSED", productId: DEMO_PRODUCT_ID };
    }
    if (action === "resume") {
      plane.activateProduct(DEMO_PRODUCT_ID);
      return { state: "ACTIVE", productId: DEMO_PRODUCT_ID };
    }
    if (action === "reset") {
      this.scenario = createDemoScenario();
      this.workflow = new MemoryWorkflowAdapter(this.scenario.plane);
      this.lastExceptionCaseId = null;
      return { state: "RESET" };
    }
    throw runtimeError("UNKNOWN_ACTION", "unsupported action");
  }

  async prepareConfidentialTransfer(command, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.confidentialTransferService.prepare({
      ...command,
      authorizedBy: identity.principalId,
      tenantId: identity.tenantId ?? this.tenantId,
      originatingInstitutionId: identity.institutionId,
    });
  }

  async registerNoteOwnerKey(command, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.confidentialTransferService.registerOwnerKey({
      tenantId: identity.tenantId, productId: command?.productId, subjectRef: command?.subjectRef,
      credentialId: command?.credentialId, ownerPublicKey: command?.ownerPublicKey,
      registeredBy: identity.principalId, actorInstitutionId: identity.institutionId,
    });
  }

  async revokeNoteOwnerKey(command, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.confidentialTransferService.revokeOwnerKey({
      tenantId: identity.tenantId, productId: command?.productId, ownerPublicKey: command?.ownerPublicKey,
      revokedBy: identity.principalId, reason: command?.reason,
    });
  }

  async authorizeConfidentialTransfer(transactionId, proofPublicInputs, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.zkSettlementGate.authorize({
      transactionId,
      tenantId: identity.tenantId,
      proofPublicInputs,
      actorInstitutionId: identity.institutionId ?? "",
    });
  }

  async settleConfidentialTransfer(transactionId, { proof, publicSignals }, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.zkSettlementGate.accept({
      transactionId,
      tenantId: identity.tenantId,
      proof,
      publicSignals,
      actorInstitutionId: identity.role === "operations" ? undefined : (identity.institutionId ?? ""),
    });
  }

  async proposeConfidentialFinality(transactionId, command, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.zkSettlementGate.proposeFinalization({
      transactionId,
      tenantId: identity.tenantId,
      outputMerkleRoot: command.outputMerkleRoot,
      outputTreeSize: command.outputTreeSize,
      rootSourceReference: command.rootSourceReference,
      executionReference: command.executionReference,
      proposedBy: identity.principalId,
    });
  }

  async approveConfidentialFinality(transactionId, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.zkSettlementGate.finalize({
      transactionId,
      tenantId: identity.tenantId,
      finalizedBy: identity.principalId,
    });
  }

  async cancelConfidentialFinality(transactionId, command, identity) {
    this.#assertTenant(identity);
    this.#requireConfidentialSettlement();
    return this.zkSettlementGate.cancelFinalization({
      transactionId,
      tenantId: identity.tenantId,
      cancelledBy: identity.principalId,
      reason: command?.reason,
    });
  }

  async proposeZkParameters(command, identity) {
    this.#assertTenant(identity);
    if (!this.zkGovernanceService) throw runtimeError("CONFIDENTIAL_SETTLEMENT_DISABLED", "ZK governance requires Groth16 mode");
    return this.zkGovernanceService.propose({
      tenantId: identity.tenantId, kind: command?.kind, input: command, proposedBy: identity.principalId,
    });
  }

  async decideZkParameters(proposalId, command, identity) {
    this.#assertTenant(identity);
    if (!this.zkGovernanceService) throw runtimeError("CONFIDENTIAL_SETTLEMENT_DISABLED", "ZK governance requires Groth16 mode");
    return this.zkGovernanceService.decide({
      tenantId: identity.tenantId, proposalId, decision: command?.decision, reason: command?.reason,
      decidedBy: identity.principalId,
    });
  }

  async requestProverJob(transactionId, witnessReference, identity) {
    this.#assertTenant(identity);
    if (!this.proverJobService) throw runtimeError("ISOLATED_PROVER_DISABLED", "isolated prover service is not enabled");
    return this.proverJobService.request({
      transactionId, tenantId: identity.tenantId, witnessReference, requestedBy: identity.principalId,
      actorInstitutionId: identity.institutionId ?? "",
    });
  }

  async proverJob(transactionId, identity) {
    this.#assertTenant(identity);
    if (!this.proverJobService) throw runtimeError("ISOLATED_PROVER_DISABLED", "isolated prover service is not enabled");
    return this.proverJobService.get({
      transactionId, tenantId: identity.tenantId,
      actorInstitutionId: identity.role === "operations" ? undefined : (identity.institutionId ?? ""),
    });
  }

  async runProverJobOnce(workerId) {
    if (!this.proverJobService) throw runtimeError("ISOLATED_PROVER_DISABLED", "isolated prover service is not enabled");
    return this.proverJobService.runOnce({ workerId });
  }

  async receiveInstitutionCallback(envelope) {
    if (!this.institutionCallbackService) {
      throw runtimeError("INSTITUTION_CONNECTOR_DISABLED", "institution callback connector requires PostgreSQL mode");
    }
    return this.institutionCallbackService.receive(envelope);
  }

  #requireConfidentialSettlement() {
    if (!this.confidentialTransferService || !this.zkSettlementGate) {
      throw runtimeError("CONFIDENTIAL_SETTLEMENT_DISABLED", "verified confidential settlement is not enabled");
    }
  }

  #assertSigningKeyInstitution(identity, institutionId) {
    // institutionId comes from the server-side session membership, never the
    // request payload. Tenant-wide key-management permission alone is not
    // authority to provision another institution's evidence signing keys.
    if (!identity?.tenantId || identity.tenantId !== this.tenantId
        || typeof identity?.institutionId !== "string" || !identity.institutionId
        || identity.institutionId !== institutionId) {
      throw runtimeError("AUTHORIZATION_DENIED", "signing-key management requires membership in the target institution");
    }
  }

  #assertTenant(identity) {
    if (identity?.tenantId && identity.tenantId !== this.tenantId) {
      throw runtimeError("TENANT_SCOPE_MISMATCH", "identity tenant is outside this product runtime scope");
    }
  }

  async close() {
    if (this.storageMode === "postgres") await this.workflow.close();
  }

  async #latestExceptionCase(status) {
    const result = await this.store.pool.query(
      `SELECT e.id FROM rwa.exception_cases e
       JOIN rwa.transaction_intents t ON t.id=e.transaction_id
       WHERE t.tenant_id=$3 AND e.product_id=$1 AND e.status=$2
       ORDER BY e.opened_at DESC,e.id DESC LIMIT 1`,
      [DEMO_PRODUCT_ID, status, this.tenantId],
    );
    return result.rows[0]?.id ?? null;
  }
}
