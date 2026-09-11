// Technical configuration drafts only. Never represents a legal eligibility decision.
import { validateTenantInput, validateProductInput } from './storage/product-catalog-service.js';

const profiles = {
  HK: { name: 'Hong Kong', timezone: 'Asia/Hong_Kong', localCurrency: 'HKD' },
  SG: { name: 'Singapore', timezone: 'Asia/Singapore', localCurrency: 'SGD' },
  MY: { name: 'Malaysia', timezone: 'Asia/Kuala_Lumpur', localCurrency: 'MYR' },
  AE: { name: 'United Arab Emirates', timezone: 'Asia/Dubai', localCurrency: 'AED' },
};
export function listMarketProfiles() {
  return Object.entries(profiles).map(([jurisdiction, profile]) => ({ jurisdiction, ...profile }));
}

export function buildMarketDraft(input, template) {
  const profile = profiles[input?.market];
  if (!profile || !Object.hasOwn(profiles, input.market)) throw new Error('unsupported market');
  if (!input.policy || typeof input.policy !== 'object' || Array.isArray(input.policy)) throw new Error('explicit policy required');
  // Do not inherit Hong Kong or generic "professional" eligibility from legacy templates.
  for (const field of ['allowedInvestorClasses', 'allowedJurisdictions', 'maxPriceDeviationBps']) {
    if (!Object.hasOwn(input.policy, field)) throw new Error('explicit policy required: ' + field);
  }
  if (!Array.isArray(input.policy.allowedJurisdictions)
    || input.policy.allowedJurisdictions.length !== 1 || input.policy.allowedJurisdictions[0] !== input.market) {
    throw new Error('initial market drafts are single-market; cross-border distribution requires a separate reviewed design');
  }
  if (typeof input.regime !== 'string' || !/^[a-z][a-z0-9-]{2,63}$/.test(input.regime)) {
    throw new Error('explicit bounded regime identifier required; a country code is not a license');
  }
  const tenant = validateTenantInput(input.tenant);
  if (tenant.homeJurisdiction !== input.market) throw new Error('tenant home jurisdiction must match this draft');
  const product = validateProductInput({ ...input.product, jurisdiction: input.market, rules: {
    allowedInvestorClasses: input.policy.allowedInvestorClasses,
    allowedJurisdictions: input.policy.allowedJurisdictions,
    maxPriceDeviationBps: input.policy.maxPriceDeviationBps,
  } }, template);
  if (input.product?.jurisdiction !== input.market) throw new Error('product jurisdiction must match market');
  if (!['FUND_V1','PRIVATE_CREDIT_V1','BOND_V1','SUKUK_V1','COMMODITY_V1'].includes(template.id)) {
    throw new Error('unsupported catalog template');
  }
  return {
    schema: 'rwa.market-draft.v1', state: 'DRAFT_NOT_APPROVED', market: input.market,
    regime: input.regime, profile: { ...profile }, tenant, product,
    legalEligibilityVerified: false, dataResidencyVerified: false,
    blockers: ['INSTITUTION_ONBOARDING', 'SIGNED_ACTIVATION_EVIDENCE', 'MAKER_CHECKER_APPROVAL',
      'LOCAL_LEGAL_ELIGIBILITY_REVIEW', 'DEPLOYMENT_DATA_BOUNDARY_VERIFICATION'],
    lifecycleBoundary: template.id === 'FUND_V1' ? 'EXISTING_FUND_WORKFLOW_REQUIRES_ACCEPTANCE'
      : 'CATALOG_CONFIGURATION_ONLY_NOT_COMPLETE_ASSET_LIFECYCLE',
  };
}
