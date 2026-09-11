import { ControlPlane, createSandboxInstitution } from "../src/control-plane.js";

const now = () => new Date("2026-08-23T12:00:00Z");
const plane = new ControlPlane({ now });
const institutions = {
  issuer: createSandboxInstitution({ id: "demo-issuer", roles: ["issuer"] }),
  broker: createSandboxInstitution({ id: "demo-broker", roles: ["distributor"] }),
  kyc: createSandboxInstitution({ id: "demo-kyc", roles: ["credential_issuer"] }),
  admin: createSandboxInstitution({ id: "demo-admin", roles: ["fund_administrator"] }),
  custodian: createSandboxInstitution({ id: "demo-custodian", roles: ["custodian"] }),
  registrar: createSandboxInstitution({ id: "demo-registrar", roles: ["transfer_agent"] }),
  bank: createSandboxInstitution({ id: "demo-bank", roles: ["cash_provider"] }),
};
for (const item of Object.values(institutions)) plane.registerInstitution(item.institution);

plane.createProduct({
  id: "hk-liquidity-sandbox",
  name: "HK Liquidity Fund — Synthetic Demo",
  jurisdiction: "HK",
  issuerId: "demo-issuer",
  roleAssignments: {
    issuer: "demo-issuer",
    distributor: "demo-broker",
    credential_issuer: "demo-kyc",
    fund_administrator: "demo-admin",
    custodian: "demo-custodian",
    transfer_agent: "demo-registrar",
    cash_provider: "demo-bank",
  },
  rules: {
    currency: "HKD",
    allowedInvestorClasses: ["professional"],
    allowedJurisdictions: ["HK", "AE"],
    maxPriceDeviationBps: 100,
  },
});
plane.activateProduct("hk-liquidity-sandbox");

plane.submitEvidence(
  institutions.admin.signStatement({
    id: "nav-demo-001",
    productId: "hk-liquidity-sandbox",
    dataType: "nav",
    sourceInstitutionId: "demo-admin",
    trustTier: "A",
    effectiveAt: "2026-08-23T00:00:00Z",
    expiresAt: "2026-08-24T00:00:00Z",
    schemaVersion: "1.0.0",
    payload: { navPerUnit: "10000", currency: "HKD", synthetic: true },
  }),
);

for (const subjectId of ["investor-a", "investor-b"]) {
  plane.registerCredential(
    institutions.kyc.signStatement({
      id: `credential-${subjectId}`,
      issuerId: "demo-kyc",
      subjectId,
      productId: "hk-liquidity-sandbox",
      investorClass: "professional",
      jurisdiction: "HK",
      maxUnits: "1000",
      validFrom: "2026-08-01T00:00:00Z",
      validUntil: "2027-08-01T00:00:00Z",
      revocationHandle: `revoke-${subjectId}`,
    }),
  );
}

plane.creditSandboxCash("investor-a", "HKD", "2000000");
plane.creditSandboxCash("investor-b", "HKD", "1000000");

const subscription = plane.subscribe({
  id: "subscription-001",
  idempotencyKey: "demo-subscription-001",
  productId: "hk-liquidity-sandbox",
  investorId: "investor-a",
  credentialId: "credential-investor-a",
  units: "100",
  cashAmount: "1000000",
});

const transfer = plane.transfer({
  id: "transfer-001",
  idempotencyKey: "demo-transfer-001",
  productId: "hk-liquidity-sandbox",
  sellerId: "investor-a",
  sellerCredentialId: "credential-investor-a",
  buyerId: "investor-b",
  buyerCredentialId: "credential-investor-b",
  units: "25",
  pricePerUnit: "10000",
  fee: "100",
  expiresAt: "2026-08-23T12:05:00Z",
});

console.log(JSON.stringify({
  warning: "SYNTHETIC SANDBOX — no real asset, money, institution or ZK proof",
  subscription,
  transfer,
  reconciliation: plane.reconcile("hk-liquidity-sandbox"),
  auditEventCount: plane.eventsForAudit().length,
}, null, 2));
