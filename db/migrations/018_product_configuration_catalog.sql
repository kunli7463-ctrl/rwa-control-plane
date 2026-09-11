CREATE TABLE IF NOT EXISTS rwa.platform_tenants (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
  legal_name text NOT NULL CHECK (char_length(legal_name) BETWEEN 2 AND 200),
  home_jurisdiction text NOT NULL CHECK (home_jurisdiction ~ '^[A-Z]{2}$'),
  data_region text NOT NULL CHECK (data_region ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  status text NOT NULL CHECK (status IN ('ONBOARDING','ACTIVE','SUSPENDED','CLOSED')),
  configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(configuration)='object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rwa.product_templates (
  id text PRIMARY KEY CHECK (id ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  asset_class text NOT NULL CHECK (asset_class IN
    ('FUND','PRIVATE_CREDIT','BOND','SUKUK','COMMODITY','RECEIVABLE')),
  version integer NOT NULL CHECK (version > 0),
  display_name text NOT NULL,
  required_roles jsonb NOT NULL CHECK (jsonb_typeof(required_roles)='array'),
  lifecycle_actions jsonb NOT NULL CHECK (jsonb_typeof(lifecycle_actions)='array'),
  default_rules jsonb NOT NULL CHECK (jsonb_typeof(default_rules)='object'),
  status text NOT NULL CHECK (status IN ('ACTIVE','RETIRED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (asset_class,version)
);

CREATE TABLE IF NOT EXISTS rwa.tenant_institutions (
  tenant_id text NOT NULL REFERENCES rwa.platform_tenants(id),
  institution_id text NOT NULL REFERENCES rwa.institutions(id),
  onboarding_status text NOT NULL CHECK (onboarding_status IN
    ('DRAFT','DUE_DILIGENCE','APPROVED','SUSPENDED','REJECTED')),
  external_reference text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,institution_id)
);

CREATE TABLE IF NOT EXISTS rwa.product_configurations (
  product_id text PRIMARY KEY REFERENCES rwa.products(id),
  tenant_id text NOT NULL REFERENCES rwa.platform_tenants(id),
  template_id text NOT NULL REFERENCES rwa.product_templates(id),
  configuration_status text NOT NULL CHECK (configuration_status IN
    ('DRAFT','ROLES_PENDING','READY_FOR_EVIDENCE','SUSPENDED','RETIRED')),
  configuration_version bigint NOT NULL DEFAULT 1 CHECK (configuration_version > 0),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id,product_id)
);

CREATE INDEX IF NOT EXISTS product_configurations_tenant_idx
  ON rwa.product_configurations(tenant_id,configuration_status,product_id);

INSERT INTO rwa.product_templates
  (id,asset_class,version,display_name,required_roles,lifecycle_actions,default_rules,status)
VALUES
  ('FUND_V1','FUND',1,'基金',
   '["issuer","distributor","credential_issuer","fund_administrator","custodian","transfer_agent","cash_provider"]',
   '["SUBSCRIBE","TRANSFER","REDEEM"]',
   '{"allowedInvestorClasses":["professional"],"allowedJurisdictions":["HK"],"maxPriceDeviationBps":100}',
   'ACTIVE'),
  ('PRIVATE_CREDIT_V1','PRIVATE_CREDIT',1,'私募信贷',
   '["issuer","distributor","credential_issuer","fund_administrator","custodian","cash_provider"]',
   '["ORIGINATE","FUND","REPAY","DEFAULT"]',
   '{"allowedInvestorClasses":["professional"],"allowedJurisdictions":["HK"],"maxPriceDeviationBps":200}',
   'ACTIVE'),
  ('BOND_V1','BOND',1,'债券',
   '["issuer","distributor","credential_issuer","fund_administrator","custodian","transfer_agent","cash_provider"]',
   '["ISSUE","TRANSFER","COUPON","MATURE"]',
   '{"allowedInvestorClasses":["professional"],"allowedJurisdictions":["HK"],"maxPriceDeviationBps":100}',
   'ACTIVE'),
  ('SUKUK_V1','SUKUK',1,'Sukuk',
   '["issuer","distributor","credential_issuer","fund_administrator","custodian","transfer_agent","cash_provider"]',
   '["ISSUE","TRANSFER","DISTRIBUTE","MATURE"]',
   '{"allowedInvestorClasses":["professional"],"allowedJurisdictions":["AE"],"maxPriceDeviationBps":100}',
   'ACTIVE'),
  ('COMMODITY_V1','COMMODITY',1,'商品与仓单',
   '["issuer","distributor","credential_issuer","custodian","transfer_agent","cash_provider"]',
   '["MINT","TRANSFER","REDEEM_PHYSICAL"]',
   '{"allowedInvestorClasses":["professional"],"allowedJurisdictions":["HK","AE"],"maxPriceDeviationBps":250}',
   'ACTIVE')
ON CONFLICT (id) DO NOTHING;

INSERT INTO rwa.platform_tenants(id,legal_name,home_jurisdiction,data_region,status,configuration)
VALUES ('sandbox-hk','RWA Synthetic Sandbox','HK','hk-local','ACTIVE','{"syntheticOnly":true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO rwa.tenant_institutions(tenant_id,institution_id,onboarding_status)
SELECT 'sandbox-hk',i.id,'APPROVED'
FROM rwa.institutions i
WHERE i.id LIKE 'demo-%'
ON CONFLICT (tenant_id,institution_id) DO NOTHING;

INSERT INTO rwa.product_configurations
  (product_id,tenant_id,template_id,configuration_status,created_by)
SELECT p.id,'sandbox-hk','FUND_V1','READY_FOR_EVIDENCE','migration-018'
FROM rwa.products p
WHERE p.id='hk-liquidity-sandbox'
ON CONFLICT (product_id) DO NOTHING;

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('issuer','catalog.read'),
  ('issuer','institution.configure'),
  ('issuer','product.configure'),
  ('operations','catalog.read'),
  ('supervisor','catalog.read')
ON CONFLICT DO NOTHING;
