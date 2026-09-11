function incidentError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class ExternalIncidentService {
  constructor(store, { tenantId } = {}) {
    if (typeof tenantId !== "string" || tenantId.length < 1 || tenantId.length > 200) {
      throw incidentError("INCIDENT_TENANT_REQUIRED", "external incident service requires one bounded tenant scope");
    }
    this.store = store;
    this.tenantId = tenantId;
  }

  async propose({ incidentId, makerRef, decision, remediationReference = null, signature = null }) {
    if (!new Set(["ACKNOWLEDGE", "REMEDIATE"]).has(decision)) {
      throw incidentError("INVALID_INCIDENT_DECISION", "maker decision must be ACKNOWLEDGE or REMEDIATE");
    }
    if (decision === "REMEDIATE" && !remediationReference) {
      throw incidentError("MISSING_REMEDIATION_REFERENCE", "remediation requires an external reference");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const incident = await client.query(
        "SELECT * FROM rwa.external_reconciliation_incidents WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
        [incidentId, this.tenantId],
      );
      if (incident.rowCount !== 1 || incident.rows[0].status !== "OPEN") {
        throw incidentError("INVALID_INCIDENT_STATE", "external incident is not open");
      }
      const round = incident.rows[0].approval_round + 1;
      await client.query(
        `INSERT INTO rwa.external_incident_approvals
         (incident_id,approval_round,role,actor_ref,decision,remediation_reference,signature)
         VALUES ($1,$2,'MAKER',$3,$4,$5,$6)`,
        [incidentId, round, makerRef, decision, remediationReference, signature],
      );
      await client.query(
        `UPDATE rwa.external_reconciliation_incidents
         SET status='PENDING_APPROVAL',approval_round=$2,row_version=row_version+1 WHERE id=$1`,
        [incidentId, round],
      );
      await this.#record(client, incident.rows[0], "external_incident.proposed", {
        incidentId, round, makerRef, decision, remediationReference,
      });
      return { incidentId, state: "PENDING_APPROVAL", approvalRound: round };
    });
  }

  async decide({ incidentId, checkerRef, decision, signature = null }) {
    if (!new Set(["APPROVE", "REJECT"]).has(decision)) {
      throw incidentError("INVALID_INCIDENT_DECISION", "checker decision must be APPROVE or REJECT");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const incident = await client.query(
        "SELECT * FROM rwa.external_reconciliation_incidents WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
        [incidentId, this.tenantId],
      );
      const row = incident.rows[0];
      if (incident.rowCount !== 1 || row.status !== "PENDING_APPROVAL") {
        throw incidentError("INVALID_INCIDENT_STATE", "external incident is not pending approval");
      }
      const maker = await client.query(
        `SELECT actor_ref,decision,remediation_reference FROM rwa.external_incident_approvals
         WHERE incident_id=$1 AND approval_round=$2 AND role='MAKER'`,
        [incidentId, row.approval_round],
      );
      if (maker.rowCount !== 1) throw incidentError("INVALID_INCIDENT_STATE", "maker proposal is missing");
      if (maker.rows[0].actor_ref === checkerRef) {
        throw incidentError("MAKER_CHECKER_CONFLICT", "external incident maker and checker must differ");
      }
      await client.query(
        `INSERT INTO rwa.external_incident_approvals
         (incident_id,approval_round,role,actor_ref,decision,signature)
         VALUES ($1,$2,'CHECKER',$3,$4,$5)`,
        [incidentId, row.approval_round, checkerRef, decision, signature],
      );
      if (decision === "REJECT") {
        await client.query(
          `UPDATE rwa.external_reconciliation_incidents
           SET status='OPEN',row_version=row_version+1 WHERE id=$1`,
          [incidentId],
        );
        await this.#record(client, row, "external_incident.returned", {
          incidentId, round: row.approval_round, checkerRef,
        });
        return { incidentId, state: "OPEN", approvalRound: row.approval_round };
      }
      const resolvedState = maker.rows[0].decision === "REMEDIATE" ? "RESOLVED_REMEDIATED" : "RESOLVED_ACKNOWLEDGED";
      await client.query(
        `UPDATE rwa.external_reconciliation_incidents
         SET status=$2,remediation_reference=$3,resolved_at=clock_timestamp(),row_version=row_version+1 WHERE id=$1`,
        [incidentId, resolvedState, maker.rows[0].remediation_reference],
      );
      await this.#record(client, row, "external_incident.resolved", {
        incidentId, round: row.approval_round, makerRef: maker.rows[0].actor_ref,
        checkerRef, resolution: resolvedState, remediationReference: maker.rows[0].remediation_reference,
      });
      return { incidentId, state: resolvedState, approvalRound: row.approval_round };
    });
  }

  async #record(client, incident, eventType, metadata) {
    await this.store.recordAuditEvent(client, {
      tenantId: incident.tenant_id, eventType, aggregateType: "external_incident",
      aggregateId: incident.id, metadata,
    });
    await this.store.enqueueOutbox(client, {
      tenantId: incident.tenant_id, topic: `rwa.${eventType}`, aggregateId: incident.id, payload: metadata,
    });
  }
}
