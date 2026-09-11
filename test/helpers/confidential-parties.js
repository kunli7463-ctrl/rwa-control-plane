// Test fixtures for H1: every confidential execution instruction names an
// eligible sender and recipient, and the public recipient is a registered
// note owner key of that recipient.
export const ELIGIBLE_RULES = Object.freeze({
  allowedInvestorClasses: ["professional"],
  allowedJurisdictions: ["HK"],
});
export const ELIGIBLE_RULES_JSON = JSON.stringify(ELIGIBLE_RULES);

export async function seedConfidentialParties(query, { productId, issuerId, recipientKey, suffix }) {
  const sender = { subjectRef: `sender-${suffix}`, credentialId: `credential-sender-${suffix}` };
  const recipient = { subjectRef: `recipient-${suffix}`, credentialId: `credential-recipient-${suffix}` };
  for (const party of [sender, recipient]) {
    await query(
      `INSERT INTO rwa.credentials
       (id,product_id,issuer_id,subject_ref,investor_class,jurisdiction,max_units,valid_from,valid_until,status,signed_payload,signature)
       VALUES ($1,$2,$3,$4,'professional','HK',1000000,clock_timestamp()-interval '1 day',clock_timestamp()+interval '30 days','ACTIVE','{}'::jsonb,'test-signature')`,
      [party.credentialId, productId, issuerId, party.subjectRef],
    );
  }
  await query(
    `INSERT INTO rwa.confidential_note_owner_keys(product_id,owner_public_key,subject_ref,credential_id,status,registered_by)
     VALUES ($1,$2::numeric,$3,$4,'ACTIVE','test-distributor')`,
    [productId, String(recipientKey), recipient.subjectRef, recipient.credentialId],
  );
  return { sender, recipient };
}

export function preparedParties(parties) {
  return {
    senderInvestorId: parties.sender.subjectRef, senderCredentialId: parties.sender.credentialId,
    recipientInvestorId: parties.recipient.subjectRef, recipientCredentialId: parties.recipient.credentialId,
  };
}

export async function insertInstruction(query, { transactionId, tenantId, requestHash, fee, recipient, relayer, parties, authorizedBy = "test" }) {
  await query(
    `INSERT INTO rwa.zk_execution_instructions
     (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by,
      sender_subject_ref,sender_credential_id,recipient_subject_ref,recipient_credential_id)
     VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7,$8,$9,$10,$11)`,
    [transactionId, tenantId, requestHash, fee, recipient, relayer, authorizedBy,
      parties.sender.subjectRef, parties.sender.credentialId, parties.recipient.subjectRef, parties.recipient.credentialId],
  );
}
