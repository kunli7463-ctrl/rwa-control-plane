-- M2: once a verified proof has consumed its input nullifiers, the two
-- outputs are the only claim to that value. Rejecting or parking a
-- ROOT_PENDING confidential transfer would silently burn it, so the only
-- permitted exit is SETTLED (after server-verified root publication). A
-- mistaken or stale publication is withdrawn with a proposal cancellation
-- and re-proposed, never by abandoning the transfer.
CREATE OR REPLACE FUNCTION rwa.guard_transaction_settlement_rail() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.settlement_rail IS DISTINCT FROM OLD.settlement_rail THEN
    RAISE EXCEPTION 'transaction settlement rail is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.current_state IN ('PROOF_PENDING','ROOT_PENDING') AND NEW.settlement_rail<>'CONFIDENTIAL_NOTE' THEN
    RAISE EXCEPTION 'only confidential note transactions can await proof or root finality' USING ERRCODE='23514';
  END IF;
  IF NEW.settlement_rail='CONFIDENTIAL_NOTE' AND NEW.current_state IS DISTINCT FROM OLD.current_state
     AND NOT (
       (OLD.current_state='REQUESTED' AND NEW.current_state IN ('POLICY_CHECKED','REJECTED')) OR
       (OLD.current_state='POLICY_CHECKED' AND NEW.current_state IN ('PROOF_PENDING','REJECTED')) OR
       (OLD.current_state='PROOF_PENDING' AND NEW.current_state IN ('ROOT_PENDING','REQUIRES_REVIEW','REJECTED')) OR
       (OLD.current_state='ROOT_PENDING' AND NEW.current_state='SETTLED') OR
       (OLD.current_state='REQUIRES_REVIEW' AND NEW.current_state IN ('PENDING_APPROVAL','CANCELLED')) OR
       (OLD.current_state='PENDING_APPROVAL' AND NEW.current_state IN ('REQUIRES_REVIEW','REPLACED','CANCELLED'))
     ) THEN
    RAISE EXCEPTION 'invalid confidential transaction state transition % -> %', OLD.current_state, NEW.current_state
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
