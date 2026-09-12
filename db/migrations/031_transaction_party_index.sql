-- L5: the investor view must not decrypt every transaction in a product.
--
-- Party references stay inside the encrypted payload. Each new transaction
-- also records keyed pseudonyms (HMAC under the economic-commitment key) of
-- its investor parties, so the read model decrypts only candidate rows. The
-- index is a pre-filter: the decrypted payload is still checked for party
-- membership. Transactions without an index under the current key (created
-- before this migration, without a committer, or under a rotated key) fall
-- back to decrypt-and-check.

ALTER TABLE rwa.transaction_intents
  ADD COLUMN IF NOT EXISTS party_index_key_id text;

CREATE OR REPLACE FUNCTION rwa.guard_transaction_party_index_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.party_index_key_id IS DISTINCT FROM OLD.party_index_key_id THEN
    RAISE EXCEPTION 'transaction party index key is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS transaction_party_index_key_guard ON rwa.transaction_intents;
CREATE TRIGGER transaction_party_index_key_guard
BEFORE UPDATE OF party_index_key_id ON rwa.transaction_intents
FOR EACH ROW EXECUTE FUNCTION rwa.guard_transaction_party_index_key();

CREATE TABLE IF NOT EXISTS rwa.transaction_party_index (
  transaction_id text NOT NULL REFERENCES rwa.transaction_intents(id),
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  party_mac text NOT NULL CHECK (party_mac ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (transaction_id, party_mac)
);

CREATE INDEX IF NOT EXISTS transaction_party_index_lookup_idx
  ON rwa.transaction_party_index(tenant_id, product_id, party_mac);

DROP TRIGGER IF EXISTS append_only_guard ON rwa.transaction_party_index;
CREATE TRIGGER append_only_guard BEFORE UPDATE OR DELETE ON rwa.transaction_party_index
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();
