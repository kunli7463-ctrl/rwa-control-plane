const SETTLEMENT_OPERATIONS = new Set(["subscribe", "transfer", "redeem"]);

export function assertWorkflowAdapter(adapter) {
  for (const method of SETTLEMENT_OPERATIONS) {
    if (typeof adapter?.[method] !== "function") {
      throw new TypeError(`workflow adapter is missing ${method}()`);
    }
  }
  return adapter;
}

export class MemoryWorkflowAdapter {
  constructor(controlPlane) {
    this.controlPlane = controlPlane;
    this.mode = "memory";
  }

  async subscribe(command) {
    return this.controlPlane.subscribe(command);
  }

  async transfer(command) {
    return this.controlPlane.transfer(command);
  }

  async redeem(command) {
    return this.controlPlane.redeem(command);
  }
}

export class PostgresWorkflowAdapter {
  constructor(service) {
    this.service = service;
    this.mode = "postgres";
  }

  async subscribe(command) {
    return this.service.subscribe(command);
  }

  async transfer(command) {
    return this.service.transfer(command);
  }

  async redeem(command) {
    return this.service.redeem(command);
  }

  async setProductStatus(command) {
    return this.service.setProductStatus(command);
  }

  async restrictCredential(command) {
    return this.service.restrictCredential(command);
  }

  async simulateRegisterFailure(command) {
    return this.service.simulateRegisterFailure(command);
  }

  async proposeExceptionResolution(command) {
    return this.service.proposeExceptionResolution(command);
  }

  async approveExceptionResolution(command) {
    return this.service.approveExceptionResolution(command);
  }

  async resetSandboxDemo(command) {
    return this.service.resetSandboxDemo(command);
  }

  async close() {
    await this.service.close();
  }
}
