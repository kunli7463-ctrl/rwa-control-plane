import { readFile } from "node:fs/promises";
import {
  validateInstitutionCallbackEnvelope,
  verifyInstitutionCallbackSignature,
} from "../src/storage/institution-callback-service.js";

const [envelopePath, publicKeyPath] = process.argv.slice(2);
if (!envelopePath || !publicKeyPath) {
  console.error("usage: node scripts/verify-institution-callback.js <envelope.json> <ed25519-public-key.pem>");
  process.exit(2);
}

try {
  const envelope = JSON.parse(await readFile(envelopePath, "utf8"));
  const publicKey = await readFile(publicKeyPath, "utf8");
  const result = validateInstitutionCallbackEnvelope(envelope);
  verifyInstitutionCallbackSignature(envelope, publicKey);
  console.log(JSON.stringify({ ok: true, status: "CONFORMANT", ...result, callbackId: envelope.callbackId }));
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    status: "NON_CONFORMANT",
    code: error.code ?? "CALLBACK_CONFORMANCE_FAILED",
    error: error.message,
  }));
  process.exit(1);
}
