-- Fail closed when upgrading products that pre-date the activation-evidence gate.
-- Migration 019 deliberately did not fabricate evidence for existing products.
-- Therefore an ACTIVE legacy product with missing mandatory evidence must not
-- remain transaction-capable merely because it was active before the upgrade.

WITH legacy_products AS (
  SELECT DISTINCT c.product_id
  FROM rwa.product_configurations c
  JOIN rwa.products p ON p.id=c.product_id
  JOIN rwa.product_evidence_requirements r ON r.product_id=c.product_id
  LEFT JOIN rwa.product_activation_evidence e ON e.id=r.evidence_id
  WHERE p.status='ACTIVE'
    AND r.mandatory
    AND (r.status<>'SATISFIED' OR e.id IS NULL OR e.expires_at<=clock_timestamp())
)
UPDATE rwa.product_configurations c
SET configuration_status='SUSPENDED',
    configuration_version=configuration_version+1,
    updated_at=clock_timestamp()
FROM legacy_products legacy
WHERE c.product_id=legacy.product_id
  AND c.configuration_status<>'SUSPENDED';

UPDATE rwa.products p
SET status='PAUSED',
    row_version=row_version+1,
    updated_at=clock_timestamp()
FROM rwa.product_configurations c
WHERE c.product_id=p.id
  AND c.configuration_status='SUSPENDED'
  AND p.status='ACTIVE';

