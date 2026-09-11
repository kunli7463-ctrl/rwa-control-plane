import assert from "node:assert/strict";
import test from "node:test";
import { ProverJobService } from "../src/storage/prover-job-service.js";

test("prover worker only claims jobs from its configured tenant", async () => {
  const observed = [];
  const store = {
    async withReadCommittedTransaction(callback) {
      return callback({
        async query(sql, parameters) {
          observed.push({ sql, parameters });
          return { rowCount: 0, rows: [] };
        },
      });
    },
  };
  const service = new ProverJobService(store, {
    tenantId: "tenant-a",
    proverClient: { async submitJob() {}, async getJob() {} },
    payloadCipher: { async encrypt() {}, async decrypt() {} },
    zkSettlementGate: { async accept() {} },
    logger: { error() {} },
  });

  assert.equal(await service.runOnce({ workerId: "worker-a" }), null);
  const claim = observed.find((query) => /FOR UPDATE SKIP LOCKED/.test(query.sql));
  assert.match(claim.sql, /WHERE tenant_id=\$1/);
  assert.deepEqual(claim.parameters, ["tenant-a"]);
  const recovery = observed.find((query) => /PROVER_LEASE_EXPIRED/.test(query.sql));
  assert.match(recovery.sql, /WHERE tenant_id=\$1 AND state IN \('SUBMITTING','VERIFYING'\)/);
  assert.equal(recovery.parameters[0], "tenant-a");
});
