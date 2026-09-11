import { ControlPlane, createSandboxInstitution } from "./control-plane.js";

export const DEMO_PRODUCT_ID = "hk-liquidity-sandbox";
export const DEMO_NOW = "2026-08-23T12:00:00Z";

export function createDemoScenario() {
  const plane = new ControlPlane({ now: () => new Date(DEMO_NOW) });
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
    id: DEMO_PRODUCT_ID,
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
  plane.activateProduct(DEMO_PRODUCT_ID);

  plane.submitEvidence(
    institutions.admin.signStatement({
      id: "nav-demo-001",
      productId: DEMO_PRODUCT_ID,
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
        productId: DEMO_PRODUCT_ID,
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
  return { plane, institutions };
}

