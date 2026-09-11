import { sha256Canonical } from "./postgres-store.js";
import {
  PRODUCT_EVIDENCE_ALGORITHM,
  PRODUCT_EVIDENCE_ENVELOPE,
  assertEd25519PublicKey,
  verifyProductEvidenceSignature,
} from "../security/product-evidence.js";

const ID = /^[a-z0-9][a-z0-9-]{2,62}$/;
const INSTITUTION_ID = /^[a-z0-9][a-z0-9-]{2,99}$/;
const PRODUCT_ID = /^[a-z0-9][a-z0-9-]{2,99}$/;
const COUNTRY = /^[A-Z]{2}$/;
const CURRENCY = /^[A-Z]{3}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ROLE = new Set([
  "issuer", "distributor", "credential_issuer", "fund_administrator",
  "custodian", "transfer_agent", "cash_provider",
]);

function catalogError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function requireString(value, field, { min = 1, max = 200, pattern = null } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max || (pattern && !pattern.test(value))) {
    throw catalogError("INVALID_CATALOG_INPUT", `${field} is invalid`);
  }
  return value;
}

function stringList(value, field, pattern = null) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) {
    throw catalogError("INVALID_CATALOG_INPUT", `${field} must be a non-empty bounded array`);
  }
  const unique = [...new Set(value.map((item) => requireString(item, field, { max: 64, pattern })))];
  if (unique.length !== value.length) throw catalogError("INVALID_CATALOG_INPUT", `${field} cannot contain duplicates`);
  return unique;
}

function reviewInput(input) {
  const decision = requireString(input?.decision, "review.decision", { max: 20 });
  if (!new Set(["APPROVE", "REJECT"]).has(decision)) {
    throw catalogError("INVALID_REVIEW_DECISION", "review decision must be APPROVE or REJECT");
  }
  return { decision, reason: requireString(input?.reason, "review.reason", { min: 3, max: 1000 }) };
}

function evidenceInput(input) {
  const issuedAt = new Date(input?.issuedAt);
  const expiresAt = new Date(input?.expiresAt);
  if (!Number.isFinite(issuedAt.getTime()) || !Number.isFinite(expiresAt.getTime()) || expiresAt <= issuedAt) {
    throw catalogError("INVALID_EVIDENCE_TIME", "evidence requires a valid increasing issuedAt/expiresAt interval");
  }
  return {
    id: requireString(input?.id, "evidence.id", { min: 3, max: 100, pattern: PRODUCT_ID }),
    requirementCode: requireString(input?.requirementCode, "evidence.requirementCode", { min: 3, max: 64, pattern: /^[a-z][a-z0-9_]{2,63}$/ }),
    sourceInstitutionId: requireString(input?.sourceInstitutionId, "evidence.sourceInstitutionId", { min: 3, max: 100, pattern: INSTITUTION_ID }),
    schemaVersion: requireString(input?.schemaVersion, "evidence.schemaVersion", { max: 40 }),
    contentHash: requireString(input?.contentHash, "evidence.contentHash", { min: 64, max: 64, pattern: SHA256 }),
    envelopeVersion: requireString(input?.envelopeVersion, "evidence.envelopeVersion", { max: 80 }),
    signatureAlgorithm: requireString(input?.signatureAlgorithm, "evidence.signatureAlgorithm", { max: 40 }),
    keyId: requireString(input?.keyId, "evidence.keyId", { max: 128, pattern: KEY_ID }),
    signature: requireString(input?.signature, "evidence.signature", { min: 16, max: 16_384 }),
    issuedAt,
    expiresAt,
  };
}

function signingKeyInput(input) {
  const validFrom = new Date(input?.validFrom);
  const validUntil = input?.validUntil == null || input.validUntil === "" ? null : new Date(input.validUntil);
  if (!Number.isFinite(validFrom.getTime())
      || (validUntil && (!Number.isFinite(validUntil.getTime()) || validUntil <= validFrom))) {
    throw catalogError("INVALID_SIGNING_KEY_TIME", "signing key requires a valid increasing validity interval");
  }
  const algorithm = requireString(input?.algorithm, "signingKey.algorithm", { max: 40 });
  if (algorithm !== PRODUCT_EVIDENCE_ALGORITHM) {
    throw catalogError("UNSUPPORTED_EVIDENCE_ALGORITHM", "product evidence signing keys must use Ed25519");
  }
  const publicKeyPem = requireString(input?.publicKeyPem, "signingKey.publicKeyPem", { min: 64, max: 16_384 });
  assertEd25519PublicKey(publicKeyPem);
  return {
    keyId: requireString(input?.keyId, "signingKey.keyId", { max: 128, pattern: KEY_ID }),
    algorithm,
    publicKeyPem,
    validFrom,
    validUntil,
  };
}

export function validateTenantInput(input) {
  return {
    id: requireString(input?.id, "tenant.id", { min: 3, max: 63, pattern: ID }),
    legalName: requireString(input?.legalName, "tenant.legalName", { min: 2, max: 200 }),
    homeJurisdiction: requireString(input?.homeJurisdiction, "tenant.homeJurisdiction", { min: 2, max: 2, pattern: COUNTRY }),
    dataRegion: requireString(input?.dataRegion, "tenant.dataRegion", { min: 2, max: 63, pattern: ID }),
  };
}

export function validateInstitutionInput(input) {
  const publicKeyPem = requireString(input?.publicKeyPem, "institution.publicKeyPem", { min: 64, max: 16_384 });
  if (!publicKeyPem.includes("BEGIN PUBLIC KEY") || publicKeyPem.includes("PRIVATE KEY")) {
    throw catalogError("INVALID_INSTITUTION_KEY", "institution key must be a public-key PEM and must not contain private material");
  }
  assertEd25519PublicKey(publicKeyPem);
  return {
    id: requireString(input?.id, "institution.id", { min: 3, max: 100, pattern: INSTITUTION_ID }),
    legalName: requireString(input?.legalName, "institution.legalName", { min: 2, max: 200 }),
    jurisdiction: requireString(input?.jurisdiction, "institution.jurisdiction", { min: 2, max: 2, pattern: COUNTRY }),
    publicKeyPem,
    externalReference: input?.externalReference == null ? null
      : requireString(input.externalReference, "institution.externalReference", { max: 200 }),
  };
}

export function validateProductInput(input, template) {
  if (!template || template.status !== "ACTIVE") throw catalogError("UNKNOWN_PRODUCT_TEMPLATE", "active product template not found");
  const currency = requireString(input?.currency, "product.currency", { min: 3, max: 3, pattern: CURRENCY });
  const suppliedRules = input?.rules ?? {};
  if (!suppliedRules || typeof suppliedRules !== "object" || Array.isArray(suppliedRules)) {
    throw catalogError("INVALID_CATALOG_INPUT", "product.rules must be an object");
  }
  const rules = { ...template.defaultRules, ...suppliedRules, currency };
  rules.allowedInvestorClasses = stringList(rules.allowedInvestorClasses, "rules.allowedInvestorClasses");
  rules.allowedJurisdictions = stringList(rules.allowedJurisdictions, "rules.allowedJurisdictions", COUNTRY);
  if (!Number.isInteger(rules.maxPriceDeviationBps)
      || rules.maxPriceDeviationBps < 0 || rules.maxPriceDeviationBps > 10_000) {
    throw catalogError("INVALID_CATALOG_INPUT", "rules.maxPriceDeviationBps must be an integer from 0 to 10000");
  }
  return {
    id: requireString(input?.id, "product.id", { min: 3, max: 100, pattern: PRODUCT_ID }),
    name: requireString(input?.name, "product.name", { min: 3, max: 200 }),
    jurisdiction: requireString(input?.jurisdiction, "product.jurisdiction", { min: 2, max: 2, pattern: COUNTRY }),
    issuerId: requireString(input?.issuerId, "product.issuerId", { min: 3, max: 100, pattern: INSTITUTION_ID }),
    currency,
    templateId: template.id,
    rules,
  };
}

function rowTemplate(row) {
  return {
    id: row.id,
    assetClass: row.asset_class,
    version: row.version,
    displayName: row.display_name,
    requiredRoles: row.required_roles,
    lifecycleActions: row.lifecycle_actions,
    defaultRules: row.default_rules,
    status: row.status,
  };
}

export class ProductCatalogService {
  constructor(store, {
    now = () => new Date(),
    maxEvidenceClockSkewMs = 300_000,
    maxEvidenceValidityMs = 366 * 86_400_000,
  } = {}) {
    this.store = store;
    this.now = now;
    this.maxEvidenceClockSkewMs = maxEvidenceClockSkewMs;
    this.maxEvidenceValidityMs = maxEvidenceValidityMs;
  }

  async provisionTenant(input, actorRef = "platform-provisioner") {
    const tenant = validateTenantInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      const created = await client.query(
        `INSERT INTO rwa.platform_tenants(id,legal_name,home_jurisdiction,data_region,status,configuration)
         VALUES ($1,$2,$3,$4,'ONBOARDING','{}')
         ON CONFLICT (id) DO NOTHING RETURNING *`,
        [tenant.id, tenant.legalName, tenant.homeJurisdiction, tenant.dataRegion],
      );
      if (created.rowCount !== 1) throw catalogError("TENANT_ALREADY_EXISTS", "tenant already exists");
      await this.store.recordAuditEvent(client, {
        tenantId: tenant.id, eventType: "tenant.provisioned", aggregateType: "tenant", aggregateId: tenant.id,
        metadata: { actorRef, homeJurisdiction: tenant.homeJurisdiction, dataRegion: tenant.dataRegion },
      });
      return { id: tenant.id, status: "ONBOARDING", ...tenant };
    });
  }

  async list({ tenantId }) {
    requireString(tenantId, "tenantId", { min: 3, max: 63, pattern: ID });
    const [tenant, templates, institutions, products, requirements, institutionApprovals, activationApprovals] = await Promise.all([
      this.store.pool.query(
        `SELECT id,legal_name,home_jurisdiction,data_region,status,configuration,created_at,updated_at
         FROM rwa.platform_tenants WHERE id=$1`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT id,asset_class,version,display_name,required_roles,lifecycle_actions,default_rules,status
         FROM rwa.product_templates WHERE status='ACTIVE' ORDER BY asset_class,version DESC`,
      ),
      this.store.pool.query(
        `SELECT i.id,i.legal_name,i.jurisdiction,i.status,ti.onboarding_status,ti.external_reference
         FROM rwa.tenant_institutions ti JOIN rwa.institutions i ON i.id=ti.institution_id
         WHERE ti.tenant_id=$1 ORDER BY i.legal_name,i.id`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT p.id,p.name,p.jurisdiction,p.issuer_id,p.currency,p.status,p.rule_version,p.rules,
                c.template_id,c.configuration_status,c.configuration_version,c.created_by,c.created_at,c.updated_at,
                COALESCE(jsonb_object_agg(r.role,r.institution_id) FILTER (WHERE r.role IS NOT NULL),'{}') AS roles
         FROM rwa.product_configurations c
         JOIN rwa.products p ON p.id=c.product_id
         LEFT JOIN rwa.product_role_assignments r ON r.product_id=p.id AND r.ended_at IS NULL
         WHERE c.tenant_id=$1
         GROUP BY p.id,c.product_id,c.tenant_id,c.template_id,c.configuration_status,
                  c.configuration_version,c.created_by,c.created_at,c.updated_at
         ORDER BY c.created_at,p.id`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT r.product_id,r.requirement_code,r.responsible_role,r.description,r.mandatory,r.status,
                r.evidence_id,e.expires_at,e.content_hash,e.source_institution_id,
                e.verification_status,e.signing_key_id,e.signature_algorithm,e.canonical_payload_hash,
                e.verifier_version,e.verified_at
         FROM rwa.product_evidence_requirements r
         JOIN rwa.product_configurations c ON c.product_id=r.product_id
         LEFT JOIN rwa.product_activation_evidence e ON e.id=r.evidence_id
         WHERE c.tenant_id=$1 ORDER BY r.product_id,r.requirement_code`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT a.tenant_id,a.institution_id,a.approval_round,a.role,a.actor_ref,a.decision,a.reason,a.created_at
         FROM rwa.institution_onboarding_approvals a
         WHERE a.tenant_id=$1 ORDER BY a.institution_id,a.approval_round,a.role DESC`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT a.product_id,a.approval_round,a.role,a.actor_ref,a.decision,a.reason,a.created_at
         FROM rwa.product_activation_approvals a
         JOIN rwa.product_configurations c ON c.product_id=a.product_id
         WHERE c.tenant_id=$1 ORDER BY a.product_id,a.approval_round,a.role DESC`, [tenantId],
      ),
    ]);
    if (tenant.rowCount !== 1) throw catalogError("UNKNOWN_TENANT", "tenant not found");
    const t = tenant.rows[0];
    const requirementsByProduct = Map.groupBy(requirements.rows, (row) => row.product_id);
    const reviewsByInstitution = Map.groupBy(institutionApprovals.rows, (row) => row.institution_id);
    const activationByProduct = Map.groupBy(activationApprovals.rows, (row) => row.product_id);
    return {
      tenant: {
        id: t.id, legalName: t.legal_name, homeJurisdiction: t.home_jurisdiction,
        dataRegion: t.data_region, status: t.status, configuration: t.configuration,
      },
      templates: templates.rows.map(rowTemplate),
      institutions: institutions.rows.map((row) => ({
        id: row.id, legalName: row.legal_name, jurisdiction: row.jurisdiction,
        status: row.status, onboardingStatus: row.onboarding_status, externalReference: row.external_reference,
        reviews: (reviewsByInstitution.get(row.id) ?? []).map((item) => ({
          round: item.approval_round, role: item.role, actorRef: item.actor_ref,
          decision: item.decision, reason: item.reason, createdAt: item.created_at,
        })),
      })),
      products: products.rows.map((row) => ({
        id: row.id, name: row.name, jurisdiction: row.jurisdiction, issuerId: row.issuer_id,
        currency: row.currency, status: row.status, ruleVersion: row.rule_version, rules: row.rules,
        templateId: row.template_id, configurationStatus: row.configuration_status,
        configurationVersion: Number(row.configuration_version), roles: row.roles,
        evidenceRequirements: (requirementsByProduct.get(row.id) ?? []).map((item) => ({
          code: item.requirement_code, responsibleRole: item.responsible_role,
          description: item.description, mandatory: item.mandatory,
          status: item.status, evidenceId: item.evidence_id,
          expiresAt: item.expires_at, contentHash: item.content_hash,
          sourceInstitutionId: item.source_institution_id,
          verificationStatus: item.verification_status,
          signingKeyId: item.signing_key_id,
          signatureAlgorithm: item.signature_algorithm,
          canonicalPayloadHash: item.canonical_payload_hash,
          verifierVersion: item.verifier_version,
          verifiedAt: item.verified_at,
        })),
        activationApprovals: (activationByProduct.get(row.id) ?? []).map((item) => ({
          round: item.approval_round, role: item.role, actorRef: item.actor_ref,
          decision: item.decision, reason: item.reason, createdAt: item.created_at,
        })),
      })),
    };
  }

  async registerInstitution({ tenantId, actorRef, institution: input }) {
    const institution = validateInstitutionInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      await this.#tenant(client, tenantId);
      const created = await client.query(
        `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem)
         VALUES ($1,$2,$3,'ACTIVE',$4) ON CONFLICT (id) DO NOTHING RETURNING id`,
        [institution.id, institution.legalName, institution.jurisdiction, institution.publicKeyPem],
      );
      if (created.rowCount !== 1) throw catalogError("INSTITUTION_ALREADY_EXISTS", "institution id already exists");
      await client.query(
        `INSERT INTO rwa.tenant_institutions
         (tenant_id,institution_id,onboarding_status,external_reference)
         VALUES ($1,$2,'DUE_DILIGENCE',$3)`,
        [tenantId, institution.id, institution.externalReference],
      );
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "institution.registered", aggregateType: "institution", aggregateId: institution.id,
        metadata: { actorRef, jurisdiction: institution.jurisdiction, onboardingStatus: "DUE_DILIGENCE" },
      });
      return { ...institution, tenantId, status: "ACTIVE", onboardingStatus: "DUE_DILIGENCE" };
    });
  }

  async registerInstitutionSigningKey({ tenantId, actorRef, institutionId, input }) {
    requireString(institutionId, "institutionId", { min: 3, max: 100, pattern: INSTITUTION_ID });
    const key = signingKeyInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      await this.#approvedInstitution(client, tenantId, institutionId);
      const inserted = await client.query(
        `INSERT INTO rwa.institution_signing_keys
         (institution_id,key_id,algorithm,public_key_pem,status,valid_from,valid_until)
         VALUES ($1,$2,$3,$4,'ACTIVE',$5,$6)
         ON CONFLICT (institution_id,key_id) DO NOTHING RETURNING key_id`,
        [institutionId, key.keyId, key.algorithm, key.publicKeyPem, key.validFrom, key.validUntil],
      );
      if (inserted.rowCount !== 1) {
        throw catalogError("SIGNING_KEY_ALREADY_EXISTS", "institution signing key id already exists");
      }
      await this.#record(client, tenantId, "institution.signing_key_registered", "institution", institutionId, {
        actorRef, keyId: key.keyId, algorithm: key.algorithm,
        validFrom: key.validFrom.toISOString(), validUntil: key.validUntil?.toISOString() ?? null,
      });
      return {
        institutionId, keyId: key.keyId, algorithm: key.algorithm, status: "ACTIVE",
        validFrom: key.validFrom, validUntil: key.validUntil,
      };
    });
  }

  async revokeInstitutionSigningKey({ tenantId, actorRef, institutionId, keyId, reason }) {
    requireString(institutionId, "institutionId", { min: 3, max: 100, pattern: INSTITUTION_ID });
    requireString(keyId, "signingKey.keyId", { max: 128, pattern: KEY_ID });
    const boundedReason = requireString(reason, "signingKey.reason", { min: 3, max: 1000 });
    return this.store.withSerializableTransaction(async (client) => {
      const membership = await client.query(
        `SELECT 1 FROM rwa.tenant_institutions
         WHERE tenant_id=$1 AND institution_id=$2 FOR SHARE`,
        [tenantId, institutionId],
      );
      if (membership.rowCount !== 1) {
        throw catalogError("UNKNOWN_TENANT_INSTITUTION", "institution is not registered for this tenant");
      }
      const revokedAt = new Date(this.now());
      const updated = await client.query(
        `UPDATE rwa.institution_signing_keys
         SET status='REVOKED',revoked_at=$3,valid_until=LEAST(COALESCE(valid_until,$3),$3)
         WHERE institution_id=$1 AND key_id=$2 AND status='ACTIVE'
         RETURNING key_id`,
        [institutionId, keyId, revokedAt],
      );
      if (updated.rowCount !== 1) {
        throw catalogError("SIGNING_KEY_NOT_ACTIVE", "institution signing key is missing or not active");
      }
      await this.#record(client, tenantId, "institution.signing_key_revoked", "institution", institutionId, {
        actorRef, keyId, reason: boundedReason, revokedAt: revokedAt.toISOString(),
      });
      return { institutionId, keyId, status: "REVOKED", revokedAt };
    });
  }

  async createProduct({ tenantId, actorRef, product: input }) {
    return this.store.withSerializableTransaction(async (client) => {
      await this.#tenant(client, tenantId);
      const templateResult = await client.query(
        `SELECT id,asset_class,version,display_name,required_roles,lifecycle_actions,default_rules,status
         FROM rwa.product_templates WHERE id=$1`, [input?.templateId],
      );
      const template = templateResult.rowCount === 1 ? rowTemplate(templateResult.rows[0]) : null;
      const product = validateProductInput(input, template);
      await this.#approvedInstitution(client, tenantId, product.issuerId);
      const created = await client.query(
        `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules)
         VALUES ($1,$2,$3,$4,$5,'DRAFT',1,$6::jsonb)
         ON CONFLICT (id) DO NOTHING RETURNING id`,
        [product.id, product.name, product.jurisdiction, product.issuerId, product.currency, JSON.stringify(product.rules)],
      );
      if (created.rowCount !== 1) throw catalogError("PRODUCT_ALREADY_EXISTS", "product id already exists");
      await client.query(
        `INSERT INTO rwa.product_configurations
         (product_id,tenant_id,template_id,configuration_status,created_by)
         VALUES ($1,$2,$3,'ROLES_PENDING',$4)`,
        [product.id, tenantId, product.templateId, actorRef],
      );
      await client.query(
        `INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at)
         VALUES ($1,'issuer',$2,clock_timestamp())`, [product.id, product.issuerId],
      );
      await client.query(
        `INSERT INTO rwa.product_evidence_requirements
         (product_id,requirement_code,responsible_role,description,mandatory)
         SELECT $1,requirement_code,responsible_role,description,mandatory
         FROM rwa.product_template_evidence_requirements WHERE template_id=$2`,
        [product.id, product.templateId],
      );
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "product.draft_created", aggregateType: "product", aggregateId: product.id,
        metadata: { actorRef, templateId: product.templateId, jurisdiction: product.jurisdiction, currency: product.currency },
      });
      await this.#snapshot(client, tenantId, product.id, actorRef, "product.draft_created");
      return { ...product, tenantId, status: "DRAFT", configurationStatus: "ROLES_PENDING", roles: { issuer: product.issuerId } };
    });
  }

  async assignRole({ tenantId, actorRef, productId, role, institutionId }) {
    requireString(productId, "productId", { min: 3, max: 100, pattern: PRODUCT_ID });
    requireString(institutionId, "institutionId", { min: 3, max: 100, pattern: INSTITUTION_ID });
    if (!ROLE.has(role)) throw catalogError("INVALID_PRODUCT_ROLE", "unsupported product role");
    return this.store.withSerializableTransaction(async (client) => {
      const product = await this.#product(client, tenantId, productId, true);
      if (product.status !== "DRAFT") throw catalogError("PRODUCT_CONFIGURATION_LOCKED", "only draft products can change role assignments");
      await this.#approvedInstitution(client, tenantId, institutionId);
      if (!product.required_roles.includes(role)) throw catalogError("ROLE_NOT_REQUIRED_BY_TEMPLATE", "role is not part of this product template");
      await client.query(
        `UPDATE rwa.product_role_assignments SET ended_at=clock_timestamp()
         WHERE product_id=$1 AND role=$2 AND ended_at IS NULL`, [productId, role],
      );
      await client.query(
        `INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at)
         VALUES ($1,$2,$3,clock_timestamp())`, [productId, role, institutionId],
      );
      const status = await this.#refreshConfigurationStatus(client, productId, product.required_roles);
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "product.role_assigned", aggregateType: "product", aggregateId: productId,
        metadata: { actorRef, role, institutionId, configurationStatus: status },
      });
      await this.#snapshot(client, tenantId, productId, actorRef, "product.role_assigned");
      return { productId, role, institutionId, configurationStatus: status };
    });
  }

  async proposeInstitutionReview({ tenantId, actorRef, institutionId, input }) {
    requireString(institutionId, "institutionId", { min: 3, max: 100, pattern: INSTITUTION_ID });
    const review = reviewInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      await this.#tenant(client, tenantId);
      const institution = await client.query(
        `SELECT onboarding_status FROM rwa.tenant_institutions
         WHERE tenant_id=$1 AND institution_id=$2 FOR UPDATE`, [tenantId, institutionId],
      );
      if (institution.rowCount !== 1 || institution.rows[0].onboarding_status !== "DUE_DILIGENCE") {
        throw catalogError("INSTITUTION_NOT_REVIEWABLE", "institution must be in DUE_DILIGENCE");
      }
      const latest = await client.query(
        `SELECT approval_round,role FROM rwa.institution_onboarding_approvals
         WHERE tenant_id=$1 AND institution_id=$2 ORDER BY approval_round DESC,role LIMIT 1`,
        [tenantId, institutionId],
      );
      const lastRound = latest.rowCount ? latest.rows[0].approval_round : 0;
      const pending = lastRound > 0 && !(await client.query(
        `SELECT 1 FROM rwa.institution_onboarding_approvals
         WHERE tenant_id=$1 AND institution_id=$2 AND approval_round=$3 AND role='CHECKER'`,
        [tenantId, institutionId, lastRound],
      )).rowCount;
      if (pending) throw catalogError("INSTITUTION_REVIEW_PENDING", "institution already has a pending maker proposal");
      const round = lastRound + 1;
      await client.query(
        `INSERT INTO rwa.institution_onboarding_approvals
         (tenant_id,institution_id,approval_round,role,actor_ref,decision,reason)
         VALUES ($1,$2,$3,'MAKER',$4,$5,$6)`,
        [tenantId, institutionId, round, actorRef, review.decision, review.reason],
      );
      await this.#record(client, tenantId, "institution.review_proposed", "institution", institutionId, {
        actorRef, round, decision: review.decision, reason: review.reason,
      });
      return { institutionId, round, state: "PENDING_APPROVAL", makerDecision: review.decision };
    });
  }

  async decideInstitutionReview({ tenantId, actorRef, institutionId, input }) {
    requireString(institutionId, "institutionId", { min: 3, max: 100, pattern: INSTITUTION_ID });
    const review = reviewInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      const institution = await client.query(
        `SELECT onboarding_status FROM rwa.tenant_institutions
         WHERE tenant_id=$1 AND institution_id=$2 FOR UPDATE`, [tenantId, institutionId],
      );
      if (institution.rowCount !== 1 || institution.rows[0].onboarding_status !== "DUE_DILIGENCE") {
        throw catalogError("INSTITUTION_NOT_REVIEWABLE", "institution must be in DUE_DILIGENCE");
      }
      const maker = await client.query(
        `SELECT approval_round,actor_ref,decision FROM rwa.institution_onboarding_approvals a
         WHERE tenant_id=$1 AND institution_id=$2 AND role='MAKER'
           AND NOT EXISTS (SELECT 1 FROM rwa.institution_onboarding_approvals c
             WHERE c.tenant_id=a.tenant_id AND c.institution_id=a.institution_id
               AND c.approval_round=a.approval_round AND c.role='CHECKER')
         ORDER BY approval_round DESC LIMIT 1 FOR SHARE`, [tenantId, institutionId],
      );
      if (maker.rowCount !== 1) throw catalogError("INSTITUTION_REVIEW_NOT_PENDING", "institution has no pending maker proposal");
      const proposal = maker.rows[0];
      if (proposal.actor_ref === actorRef) throw catalogError("MAKER_CHECKER_CONFLICT", "institution maker and checker must differ");
      await client.query(
        `INSERT INTO rwa.institution_onboarding_approvals
         (tenant_id,institution_id,approval_round,role,actor_ref,decision,reason)
         VALUES ($1,$2,$3,'CHECKER',$4,$5,$6)`,
        [tenantId, institutionId, proposal.approval_round, actorRef, review.decision, review.reason],
      );
      let state = "DUE_DILIGENCE";
      if (review.decision === "APPROVE") {
        state = proposal.decision === "APPROVE" ? "APPROVED" : "REJECTED";
        await client.query(
          `UPDATE rwa.tenant_institutions SET onboarding_status=$3,updated_at=clock_timestamp()
           WHERE tenant_id=$1 AND institution_id=$2`, [tenantId, institutionId, state],
        );
      }
      await this.#record(client, tenantId,
        review.decision === "APPROVE" ? "institution.review_decided" : "institution.review_returned",
        "institution", institutionId, {
          actorRef, round: proposal.approval_round, checkerDecision: review.decision,
          makerDecision: proposal.decision, resultingState: state, reason: review.reason,
        });
      return { institutionId, round: proposal.approval_round, state };
    });
  }

  async attachActivationEvidence({ tenantId, actorRef, productId, input }) {
    requireString(productId, "productId", { min: 3, max: 100, pattern: PRODUCT_ID });
    const evidence = evidenceInput(input);
    if (evidence.envelopeVersion !== PRODUCT_EVIDENCE_ENVELOPE) {
      throw catalogError("UNSUPPORTED_EVIDENCE_ENVELOPE", "product activation evidence envelope version is unsupported");
    }
    if (evidence.signatureAlgorithm !== PRODUCT_EVIDENCE_ALGORITHM) {
      throw catalogError("UNSUPPORTED_EVIDENCE_ALGORITHM", "product activation evidence signature algorithm is unsupported");
    }
    const now = new Date(this.now());
    if (!Number.isFinite(now.getTime())) throw catalogError("INVALID_VERIFIER_TIME", "evidence verifier time is invalid");
    if (evidence.issuedAt.getTime() - now.getTime() > this.maxEvidenceClockSkewMs) {
      throw catalogError("EVIDENCE_FROM_FUTURE", "product activation evidence issuedAt is too far in the future");
    }
    if (now >= evidence.expiresAt) throw catalogError("EVIDENCE_EXPIRED", "product activation evidence has expired");
    if (evidence.expiresAt.getTime() - evidence.issuedAt.getTime() > this.maxEvidenceValidityMs) {
      throw catalogError("EVIDENCE_VALIDITY_TOO_LONG", "product activation evidence validity exceeds policy");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const product = await this.#product(client, tenantId, productId, true);
      if (product.status !== "DRAFT") throw catalogError("PRODUCT_CONFIGURATION_LOCKED", "activation evidence can only be attached to a draft product");
      const requirement = await client.query(
        `SELECT requirement_code,responsible_role FROM rwa.product_evidence_requirements
         WHERE product_id=$1 AND requirement_code=$2 FOR UPDATE`, [productId, evidence.requirementCode],
      );
      if (requirement.rowCount !== 1) throw catalogError("UNKNOWN_EVIDENCE_REQUIREMENT", "product evidence requirement not found");
      await this.#approvedInstitution(client, tenantId, evidence.sourceInstitutionId);
      const assignment = await client.query(
        `SELECT 1 FROM rwa.product_role_assignments WHERE product_id=$1 AND role=$2
         AND institution_id=$3 AND ended_at IS NULL`,
        [productId, requirement.rows[0].responsible_role, evidence.sourceInstitutionId],
      );
      if (assignment.rowCount !== 1) {
        throw catalogError("EVIDENCE_SOURCE_ROLE_MISMATCH", "evidence source is not assigned to the responsible product role");
      }
      const signingKey = await client.query(
        `SELECT key_id,algorithm,public_key_pem,status,valid_from,valid_until,revoked_at
         FROM rwa.institution_signing_keys
         WHERE institution_id=$1 AND key_id=$2 FOR SHARE`,
        [evidence.sourceInstitutionId, evidence.keyId],
      );
      if (signingKey.rowCount !== 1) {
        throw catalogError("UNKNOWN_EVIDENCE_SIGNING_KEY", "institution evidence signing key is not registered");
      }
      const key = signingKey.rows[0];
      if (key.algorithm !== evidence.signatureAlgorithm || key.status !== "ACTIVE" || key.revoked_at) {
        throw catalogError("EVIDENCE_SIGNING_KEY_UNAVAILABLE", "institution evidence signing key is not active");
      }
      if (evidence.issuedAt < new Date(key.valid_from)
          || (key.valid_until && evidence.issuedAt >= new Date(key.valid_until))) {
        throw catalogError("EVIDENCE_SIGNING_KEY_OUTSIDE_VALIDITY", "evidence was signed outside the key validity window");
      }
      const verification = verifyProductEvidenceSignature({ tenantId, productId, ...evidence }, key.public_key_pem);
      await client.query(
        `INSERT INTO rwa.product_activation_evidence
         (id,product_id,requirement_code,source_institution_id,schema_version,content_hash,
          signature,issued_at,expires_at,received_by,envelope_version,signature_algorithm,
          signing_key_id,canonical_payload_hash,verification_status,verifier_version,verified_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'VERIFIED',$15,$16)`,
        [evidence.id, productId, evidence.requirementCode, evidence.sourceInstitutionId,
          evidence.schemaVersion, evidence.contentHash, evidence.signature,
          evidence.issuedAt, evidence.expiresAt, actorRef, evidence.envelopeVersion,
          evidence.signatureAlgorithm, evidence.keyId, verification.payloadHash,
          verification.verifierVersion, now],
      );
      await client.query(
        `UPDATE rwa.product_evidence_requirements
         SET status='SATISFIED',evidence_id=$3,updated_at=clock_timestamp()
         WHERE product_id=$1 AND requirement_code=$2`,
        [productId, evidence.requirementCode, evidence.id],
      );
      await client.query(
        `UPDATE rwa.product_configurations SET configuration_version=configuration_version+1,
         updated_at=clock_timestamp() WHERE product_id=$1`, [productId],
      );
      await this.#record(client, tenantId, "product.activation_evidence_attached", "product", productId, {
        actorRef, evidenceId: evidence.id, requirementCode: evidence.requirementCode,
        sourceInstitutionId: evidence.sourceInstitutionId, contentHash: evidence.contentHash,
        expiresAt: evidence.expiresAt.toISOString(), signingKeyId: evidence.keyId,
        signatureAlgorithm: evidence.signatureAlgorithm,
        canonicalPayloadHash: verification.payloadHash,
        verifierVersion: verification.verifierVersion,
      });
      await this.#snapshot(client, tenantId, productId, actorRef, "product.activation_evidence_attached");
      return {
        productId, evidenceId: evidence.id, requirementCode: evidence.requirementCode,
        state: "SATISFIED", verificationStatus: "VERIFIED",
        signingKeyId: evidence.keyId, canonicalPayloadHash: verification.payloadHash,
      };
    });
  }

  async proposeActivation({ tenantId, actorRef, productId, input }) {
    requireString(productId, "productId", { min: 3, max: 100, pattern: PRODUCT_ID });
    const reason = requireString(input?.reason, "activation.reason", { min: 3, max: 1000 });
    return this.store.withSerializableTransaction(async (client) => {
      const product = await this.#product(client, tenantId, productId, true);
      if (product.status !== "DRAFT" || product.configuration_status !== "READY_FOR_EVIDENCE") {
        throw catalogError("PRODUCT_NOT_READY_FOR_ACTIVATION", "product must be draft and READY_FOR_EVIDENCE");
      }
      await this.#assertActivationReady(client, tenantId, productId, product.required_roles);
      const pending = await client.query(
        `SELECT 1 FROM rwa.product_activation_approvals a WHERE product_id=$1 AND role='MAKER'
         AND NOT EXISTS (SELECT 1 FROM rwa.product_activation_approvals c
           WHERE c.product_id=a.product_id AND c.approval_round=a.approval_round AND c.role='CHECKER')`, [productId],
      );
      if (pending.rowCount) throw catalogError("ACTIVATION_ALREADY_PENDING", "product activation already has a pending proposal");
      const roundResult = await client.query(
        `SELECT COALESCE(max(approval_round),0)::int+1 AS round FROM rwa.product_activation_approvals WHERE product_id=$1`, [productId],
      );
      const round = roundResult.rows[0].round;
      await client.query(
        `INSERT INTO rwa.product_activation_approvals(product_id,approval_round,role,actor_ref,decision,reason)
         VALUES ($1,$2,'MAKER',$3,'ACTIVATE',$4)`, [productId, round, actorRef, reason],
      );
      await client.query(
        `UPDATE rwa.product_configurations SET configuration_status='ACTIVATION_PENDING',
         configuration_version=configuration_version+1,updated_at=clock_timestamp() WHERE product_id=$1`, [productId],
      );
      await this.#record(client, tenantId, "product.activation_proposed", "product", productId, { actorRef, round, reason });
      await this.#snapshot(client, tenantId, productId, actorRef, "product.activation_proposed");
      return { productId, round, state: "ACTIVATION_PENDING" };
    });
  }

  async decideActivation({ tenantId, actorRef, productId, input }) {
    requireString(productId, "productId", { min: 3, max: 100, pattern: PRODUCT_ID });
    const review = reviewInput(input);
    return this.store.withSerializableTransaction(async (client) => {
      const product = await this.#product(client, tenantId, productId, true);
      if (product.status !== "DRAFT" || product.configuration_status !== "ACTIVATION_PENDING") {
        throw catalogError("ACTIVATION_NOT_PENDING", "product activation is not pending");
      }
      const maker = await client.query(
        `SELECT approval_round,actor_ref FROM rwa.product_activation_approvals a
         WHERE product_id=$1 AND role='MAKER' AND NOT EXISTS
           (SELECT 1 FROM rwa.product_activation_approvals c WHERE c.product_id=a.product_id
            AND c.approval_round=a.approval_round AND c.role='CHECKER')
         ORDER BY approval_round DESC LIMIT 1 FOR SHARE`, [productId],
      );
      if (maker.rowCount !== 1) throw catalogError("ACTIVATION_NOT_PENDING", "activation maker proposal is missing");
      if (maker.rows[0].actor_ref === actorRef) throw catalogError("MAKER_CHECKER_CONFLICT", "activation maker and checker must differ");
      await client.query(
        `INSERT INTO rwa.product_activation_approvals(product_id,approval_round,role,actor_ref,decision,reason)
         VALUES ($1,$2,'CHECKER',$3,$4,$5)`,
        [productId, maker.rows[0].approval_round, actorRef, review.decision, review.reason],
      );
      let state = "READY_FOR_EVIDENCE";
      if (review.decision === "APPROVE") {
        await this.#assertActivationReady(client, tenantId, productId, product.required_roles);
        await client.query(
          `UPDATE rwa.products SET status='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp()
           WHERE id=$1 AND status='DRAFT'`, [productId],
        );
        state = "ACTIVE";
      }
      await client.query(
        `UPDATE rwa.product_configurations SET configuration_status=$2,
         configuration_version=configuration_version+1,updated_at=clock_timestamp() WHERE product_id=$1`,
        [productId, state],
      );
      await this.#record(client, tenantId,
        review.decision === "APPROVE" ? "product.activation_approved" : "product.activation_rejected",
        "product", productId, {
          actorRef, round: maker.rows[0].approval_round, decision: review.decision,
          reason: review.reason, resultingState: state,
        });
      await this.#snapshot(client, tenantId, productId, actorRef,
        review.decision === "APPROVE" ? "product.activation_approved" : "product.activation_rejected");
      return { productId, round: maker.rows[0].approval_round, state };
    });
  }

  async auditExport({ tenantId }) {
    const catalog = await this.list({ tenantId });
    const [snapshots, audit] = await Promise.all([
      this.store.pool.query(
        `SELECT product_id,configuration_version,event_type,actor_ref,snapshot_hash,created_at
         FROM rwa.product_configuration_snapshots WHERE tenant_id=$1
         ORDER BY sequence_id DESC LIMIT 500`, [tenantId],
      ),
      this.store.pool.query(
        `SELECT sequence_id,event_type,aggregate_type,aggregate_id,metadata,occurred_at,event_hash
         FROM rwa.audit_events WHERE tenant_id=$1 AND aggregate_type IN ('product','institution','tenant')
         ORDER BY sequence_id DESC LIMIT 1000`, [tenantId],
      ),
    ]);
    const report = {
      generatedAt: new Date().toISOString(), tenant: catalog.tenant,
      templates: catalog.templates.map(({ id, assetClass, version }) => ({ id, assetClass, version })),
      institutions: catalog.institutions,
      products: catalog.products,
      snapshots: snapshots.rows.map((row) => ({
        productId: row.product_id, configurationVersion: Number(row.configuration_version),
        eventType: row.event_type, actorRef: row.actor_ref,
        snapshotHash: row.snapshot_hash, createdAt: row.created_at,
      })),
      auditEvents: audit.rows.map((row) => ({
        sequenceId: Number(row.sequence_id), eventType: row.event_type,
        aggregateType: row.aggregate_type, aggregateId: row.aggregate_id,
        metadata: row.metadata, occurredAt: row.occurred_at, eventHash: row.event_hash,
      })),
    };
    return { ...report, exportHash: sha256Canonical(report) };
  }

  async #tenant(client, tenantId) {
    requireString(tenantId, "tenantId", { min: 3, max: 63, pattern: ID });
    const result = await client.query(
      `SELECT id,status FROM rwa.platform_tenants WHERE id=$1 FOR SHARE`, [tenantId],
    );
    if (result.rowCount !== 1) throw catalogError("UNKNOWN_TENANT", "tenant not found");
    if (!new Set(["ONBOARDING", "ACTIVE"]).has(result.rows[0].status)) {
      throw catalogError("TENANT_NOT_ACTIVE", "tenant cannot be configured in its current state");
    }
    return result.rows[0];
  }

  async #approvedInstitution(client, tenantId, institutionId) {
    const result = await client.query(
      `SELECT i.id FROM rwa.tenant_institutions ti JOIN rwa.institutions i ON i.id=ti.institution_id
       WHERE ti.tenant_id=$1 AND ti.institution_id=$2 AND ti.onboarding_status='APPROVED' AND i.status='ACTIVE'
       FOR SHARE OF ti,i`, [tenantId, institutionId],
    );
    if (result.rowCount !== 1) throw catalogError("INSTITUTION_NOT_APPROVED", "institution is not active and approved for this tenant");
    return result.rows[0];
  }

  async #product(client, tenantId, productId, lock = false) {
    const result = await client.query(
      `SELECT p.id,p.status,c.template_id,c.configuration_status,c.configuration_version,t.required_roles
       FROM rwa.product_configurations c JOIN rwa.products p ON p.id=c.product_id
       JOIN rwa.product_templates t ON t.id=c.template_id
       WHERE c.tenant_id=$1 AND p.id=$2 ${lock ? "FOR UPDATE OF p,c" : ""}`,
      [tenantId, productId],
    );
    if (result.rowCount !== 1) throw catalogError("UNKNOWN_PRODUCT", "product not found for tenant");
    return result.rows[0];
  }

  async #assertActivationReady(client, tenantId, productId, requiredRoles) {
    const assignments = await client.query(
      `SELECT r.role,r.institution_id,ti.onboarding_status,i.status
       FROM rwa.product_role_assignments r
       JOIN rwa.tenant_institutions ti ON ti.tenant_id=$2 AND ti.institution_id=r.institution_id
       JOIN rwa.institutions i ON i.id=r.institution_id
       WHERE r.product_id=$1 AND r.ended_at IS NULL`, [productId, tenantId],
    );
    const validRoles = new Set(assignments.rows
      .filter((row) => row.onboarding_status === "APPROVED" && row.status === "ACTIVE")
      .map((row) => row.role));
    if (!requiredRoles.every((role) => validRoles.has(role))) {
      throw catalogError("ACTIVATION_ROLE_NOT_APPROVED", "every required role must have an active approved institution");
    }
    const missing = await client.query(
      `SELECT r.requirement_code FROM rwa.product_evidence_requirements r
       LEFT JOIN rwa.product_activation_evidence e ON e.id=r.evidence_id
       LEFT JOIN rwa.institution_signing_keys k
         ON k.institution_id=e.source_institution_id AND k.key_id=e.signing_key_id
       WHERE r.product_id=$1 AND r.mandatory
         AND (r.status<>'SATISFIED' OR e.id IS NULL OR e.expires_at<=clock_timestamp()
           OR e.verification_status<>'VERIFIED' OR k.status<>'ACTIVE' OR k.revoked_at IS NOT NULL
           OR e.issued_at<k.valid_from OR (k.valid_until IS NOT NULL AND e.issued_at>=k.valid_until))
       ORDER BY r.requirement_code`, [productId],
    );
    if (missing.rowCount) {
      const error = catalogError("ACTIVATION_EVIDENCE_INCOMPLETE", "mandatory activation evidence is missing or expired");
      error.details = { missingRequirements: missing.rows.map((row) => row.requirement_code) };
      throw error;
    }
  }

  async #snapshot(client, tenantId, productId, actorRef, eventType) {
    // Preserve the same transaction snapshot without concurrent client.query.
    const [configuration, roles, requirements] = [
      await client.query(
        `SELECT p.id,p.name,p.jurisdiction,p.issuer_id,p.currency,p.status,p.rule_version,p.rules,
                c.template_id,c.configuration_status,c.configuration_version
         FROM rwa.products p JOIN rwa.product_configurations c ON c.product_id=p.id
         WHERE p.id=$1 AND c.tenant_id=$2`, [productId, tenantId],
      ),
      await client.query(
        `SELECT role,institution_id FROM rwa.product_role_assignments
         WHERE product_id=$1 AND ended_at IS NULL ORDER BY role`, [productId],
      ),
      await client.query(
        `SELECT requirement_code,responsible_role,mandatory,status,evidence_id
         FROM rwa.product_evidence_requirements WHERE product_id=$1 ORDER BY requirement_code`, [productId],
      ),
    ];
    if (configuration.rowCount !== 1) throw catalogError("UNKNOWN_PRODUCT", "cannot snapshot missing tenant product");
    const row = configuration.rows[0];
    const snapshot = {
      product: {
        id: row.id, name: row.name, jurisdiction: row.jurisdiction, issuerId: row.issuer_id,
        currency: row.currency, status: row.status, ruleVersion: row.rule_version, rules: row.rules,
      },
      configuration: {
        templateId: row.template_id, status: row.configuration_status,
        version: Number(row.configuration_version),
      },
      roles: Object.fromEntries(roles.rows.map((item) => [item.role, item.institution_id])),
      requirements: requirements.rows.map((item) => ({
        code: item.requirement_code, responsibleRole: item.responsible_role,
        mandatory: item.mandatory, status: item.status, evidenceId: item.evidence_id,
      })),
    };
    await client.query(
      `INSERT INTO rwa.product_configuration_snapshots
       (tenant_id,product_id,configuration_version,event_type,actor_ref,snapshot,snapshot_hash)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
       ON CONFLICT (product_id,configuration_version) DO NOTHING`,
      [tenantId, productId, row.configuration_version, eventType, actorRef,
        JSON.stringify(snapshot), sha256Canonical(snapshot)],
    );
  }

  async #record(client, tenantId, eventType, aggregateType, aggregateId, metadata) {
    await this.store.recordAuditEvent(client, { tenantId, eventType, aggregateType, aggregateId, metadata });
    await this.store.enqueueOutbox(client, {
      tenantId, topic: `rwa.${eventType}`, aggregateId, payload: metadata,
    });
  }

  async #refreshConfigurationStatus(client, productId, requiredRoles) {
    const assigned = await client.query(
      `SELECT role FROM rwa.product_role_assignments WHERE product_id=$1 AND ended_at IS NULL`, [productId],
    );
    const active = new Set(assigned.rows.map((row) => row.role));
    const complete = requiredRoles.every((role) => active.has(role));
    const status = complete ? "READY_FOR_EVIDENCE" : "ROLES_PENDING";
    await client.query(
      `UPDATE rwa.product_configurations
       SET configuration_status=$2,configuration_version=configuration_version+1,updated_at=clock_timestamp()
       WHERE product_id=$1`, [productId, status],
    );
    return status;
  }
}
