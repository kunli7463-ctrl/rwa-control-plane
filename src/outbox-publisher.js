import { resolve } from "node:path";
import { SimulatedRegisterCallbackConsumer } from "./storage/outbox-dispatcher.js";

function publisherError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export async function createOutboxPublisher({
  deploymentProfile = "sandbox",
  store,
  modulePath = null,
  tenantId,
  cwd = process.cwd(),
  importer = (specifier) => import(specifier),
} = {}) {
  if (deploymentProfile === "sandbox") {
    const consumer = new SimulatedRegisterCallbackConsumer({ store });
    return { mode: "SIMULATED_SANDBOX", publish: (event) => consumer.consume(event) };
  }
  if (deploymentProfile !== "production") {
    throw publisherError("INVALID_DEPLOYMENT_PROFILE", "outbox publisher profile must be sandbox or production");
  }
  if (!tenantId || tenantId === "sandbox-hk") {
    throw publisherError("PRODUCTION_TENANT_REQUIRED", "production publisher requires a non-sandbox tenant");
  }
  if (!modulePath) {
    throw publisherError("OUTBOX_PUBLISHER_REQUIRED", "production requires OUTBOX_PUBLISHER_MODULE");
  }
  let publisherModule;
  try {
    publisherModule = await importer(resolve(cwd, modulePath));
  } catch (cause) {
    throw publisherError("OUTBOX_PUBLISHER_LOAD_FAILED", `outbox publisher could not be loaded: ${cause.message}`);
  }
  const factory = publisherModule.createOutboxPublisher ?? publisherModule.default;
  if (typeof factory !== "function") {
    throw publisherError("INVALID_OUTBOX_PUBLISHER_MODULE", "publisher module must export createOutboxPublisher");
  }
  const publisher = await factory({ tenantId });
  if (!publisher || typeof publisher.publish !== "function") {
    throw publisherError("INVALID_OUTBOX_PUBLISHER", "publisher must implement publish(event)");
  }
  return { mode: "EXTERNAL_AT_LEAST_ONCE", publish: (event) => publisher.publish(event) };
}
