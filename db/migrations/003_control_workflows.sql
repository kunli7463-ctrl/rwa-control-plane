ALTER TABLE rwa.exception_cases
  ADD COLUMN approval_round integer NOT NULL DEFAULT 0 CHECK (approval_round >= 0);

ALTER TABLE rwa.approval_records
  ADD COLUMN approval_round integer NOT NULL DEFAULT 1 CHECK (approval_round > 0),
  ADD COLUMN proposed_replacement_transaction_id text;

UPDATE rwa.exception_cases e
SET approval_round = 1
WHERE EXISTS (SELECT 1 FROM rwa.approval_records a WHERE a.exception_id=e.id);

ALTER TABLE rwa.approval_records
  DROP CONSTRAINT approval_records_exception_id_role_key;

ALTER TABLE rwa.approval_records
  ADD CONSTRAINT approval_records_round_role_unique UNIQUE (exception_id, approval_round, role);

CREATE OR REPLACE FUNCTION rwa.validate_approval_record() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  maker_ref text;
BEGIN
  IF NEW.role = 'MAKER' THEN
    IF (NEW.decision = 'RETRY' AND NEW.proposed_replacement_transaction_id IS NULL)
       OR (NEW.decision = 'CANCEL' AND NEW.proposed_replacement_transaction_id IS NOT NULL) THEN
      RAISE EXCEPTION 'maker proposal payload does not match decision' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.proposed_replacement_transaction_id IS NOT NULL THEN
    RAISE EXCEPTION 'checker cannot replace maker proposal payload' USING ERRCODE = '23514';
  END IF;
  SELECT actor_ref INTO maker_ref
  FROM rwa.approval_records
  WHERE exception_id = NEW.exception_id
    AND approval_round = NEW.approval_round
    AND role = 'MAKER'
  FOR UPDATE;
  IF maker_ref IS NULL THEN
    RAISE EXCEPTION 'checker approval requires a maker proposal in the same round' USING ERRCODE = '23514';
  END IF;
  IF maker_ref = NEW.actor_ref THEN
    RAISE EXCEPTION 'maker and checker must be different actors' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER maker_checker_guard ON rwa.approval_records;
CREATE TRIGGER maker_checker_guard
BEFORE INSERT ON rwa.approval_records
FOR EACH ROW EXECUTE FUNCTION rwa.validate_approval_record();

CREATE TRIGGER approval_records_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.approval_records
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();
