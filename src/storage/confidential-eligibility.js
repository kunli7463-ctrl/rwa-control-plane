// H1 (server side): who may send and receive on the confidential note rail.
//
// Amounts are private on this rail, so holding limits cannot be checked
// here; investor status, class, jurisdiction and credential validity can.
// The public `recipient` must be a note owner key registered to the named,
// eligible recipient investor. The v3 circuit binds that key to the owner of
// the value-carrying output; with v2 the binding is only as strong as the
// circuit (see zk-candidate/circuits/confidential_ledger_v3.circom).

function eligibilityError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

export async function assertEligibleCredential(client, { productId, rules, subjectRef, credentialId, now, party }) {
  if (!Array.isArray(rules?.allowedInvestorClasses) || !Array.isArray(rules?.allowedJurisdictions)) {
    throw eligibilityError("PRODUCT_ELIGIBILITY_RULES_MISSING", "product has no investor eligibility rules for confidential transfers");
  }
  for (const [label, value] of Object.entries({ subjectRef, credentialId })) {
    if (typeof value !== "string" || value.length < 1 || value.length > 200) {
      throw eligibilityError("INVALID_CONFIDENTIAL_PARTY", `${party} ${label} must be a bounded non-empty string`);
    }
  }
  const result = await client.query(
    `SELECT subject_ref,investor_class,jurisdiction,valid_from,valid_until,status
     FROM rwa.credentials WHERE id=$1 AND product_id=$2 FOR SHARE`,
    [credentialId, productId],
  );
  const credential = result.rows[0];
  let reason = null;
  if (result.rowCount !== 1) reason = "UNKNOWN_CREDENTIAL";
  else if (credential.subject_ref !== subjectRef) reason = "CREDENTIAL_SUBJECT_MISMATCH";
  else if (new Date(credential.valid_from) > now || new Date(credential.valid_until) <= now) reason = "CREDENTIAL_NOT_CURRENT";
  else if (credential.status !== "ACTIVE") reason = "CREDENTIAL_RESTRICTED";
  else if (!rules.allowedInvestorClasses.includes(credential.investor_class)) reason = "INVESTOR_CLASS_NOT_ALLOWED";
  else if (!rules.allowedJurisdictions.includes(credential.jurisdiction)) reason = "INVESTOR_JURISDICTION_NOT_ALLOWED";
  if (reason) {
    throw eligibilityError("CONFIDENTIAL_PARTY_INELIGIBLE", `${party} is not eligible for this confidential transfer`, { party, reason });
  }
}

export async function assertRegisteredRecipientKey(client, { productId, ownerPublicKey, subjectRef, credentialId }) {
  const result = await client.query(
    `SELECT subject_ref,credential_id,status FROM rwa.confidential_note_owner_keys
     WHERE product_id=$1 AND owner_public_key=$2::numeric FOR SHARE`,
    [productId, ownerPublicKey],
  );
  const key = result.rows[0];
  if (result.rowCount !== 1 || key.status !== "ACTIVE" || key.subject_ref !== subjectRef || key.credential_id !== credentialId) {
    throw eligibilityError(
      "RECIPIENT_KEY_NOT_REGISTERED",
      "recipient is not an active note owner key registered to the named recipient credential",
    );
  }
}

/** Re-checks both parties of a stored execution instruction (authorize and accept time). */
export async function assertInstructionParties(client, { productId, rules, instruction, now }) {
  if (!instruction.sender_subject_ref || !instruction.sender_credential_id
      || !instruction.recipient_subject_ref || !instruction.recipient_credential_id) {
    throw eligibilityError("CONFIDENTIAL_PARTIES_MISSING", "execution instruction does not identify eligible sender and recipient credentials");
  }
  await assertEligibleCredential(client, {
    productId, rules, now, party: "sender",
    subjectRef: instruction.sender_subject_ref, credentialId: instruction.sender_credential_id,
  });
  await assertEligibleCredential(client, {
    productId, rules, now, party: "recipient",
    subjectRef: instruction.recipient_subject_ref, credentialId: instruction.recipient_credential_id,
  });
  await assertRegisteredRecipientKey(client, {
    productId, ownerPublicKey: String(instruction.recipient),
    subjectRef: instruction.recipient_subject_ref, credentialId: instruction.recipient_credential_id,
  });
}
