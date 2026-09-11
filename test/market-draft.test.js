import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMarketDraft, listMarketProfiles } from '../src/market-draft.js';

const template = { id: 'FUND_V1', status: 'ACTIVE', defaultRules: {
  allowedInvestorClasses: ['professional'], allowedJurisdictions: ['HK'], maxPriceDeviationBps: 100 } };
const input = (market) => ({ market, regime: 'pending-local-review',
  tenant: { id: 'tenant-' + market.toLowerCase(), legalName: 'Synthetic Draft', homeJurisdiction: market, dataRegion: 'pending-region' },
  product: { id: 'draft-' + market.toLowerCase(), name: 'Synthetic Draft', jurisdiction: market, issuerId: 'pending-issuer', currency: 'USD' },
  policy: { allowedInvestorClasses: ['synthetic-test-only'], allowedJurisdictions: [market], maxPriceDeviationBps: 50 } });

for (const market of ['HK','SG','MY','AE']) test(market + ' draft overrides inherited geography without activating or certifying compliance', () => {
  const draft = buildMarketDraft(input(market), template);
  assert.deepEqual(draft.product.rules.allowedJurisdictions, [market]);
  assert.equal(draft.state, 'DRAFT_NOT_APPROVED');
  assert.equal(draft.legalEligibilityVerified, false);
  assert.equal(draft.dataResidencyVerified, false);
  assert.ok(draft.blockers.includes('SIGNED_ACTIVATION_EVIDENCE'));
  assert.equal(draft.product.currency, 'USD');
});
test('market drafts reject omitted eligibility, inconsistent scope, unsupported markets and implicit UAE regime', () => {
  for (const field of ['allowedInvestorClasses','allowedJurisdictions','maxPriceDeviationBps']) {
    const value = input('MY'); delete value.policy[field]; assert.throws(() => buildMarketDraft(value, template));
  }
  const value = input('AE'); delete value.regime; assert.throws(() => buildMarketDraft(value, template));
  value.regime = 'selected-review-regime'; value.policy.allowedJurisdictions.push('HK');
  assert.throws(() => buildMarketDraft(value, template));
  assert.throws(() => buildMarketDraft({ ...input('SG'), market: 'US' }, template));
  assert.throws(() => buildMarketDraft({ ...input('SG'), product: input('HK').product }, template));
});
test('profiles cannot be mutated by consumers and non-fund drafts do not claim a finished lifecycle', () => {
  const list = listMarketProfiles(); list[0].name = 'changed';
  assert.equal(listMarketProfiles()[0].name, 'Hong Kong');
  const draft = buildMarketDraft(input('MY'), { ...template, id: 'SUKUK_V1' });
  assert.match(draft.lifecycleBoundary, /NOT_COMPLETE/);
  assert.deepEqual(template.defaultRules.allowedJurisdictions, ['HK']);
});
