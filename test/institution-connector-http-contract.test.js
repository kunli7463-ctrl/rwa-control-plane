import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [server, runtime] = await Promise.all([
  readFile(new URL("../src/server.js", import.meta.url), "utf8"),
  readFile(new URL("../src/demo-runtime.js", import.meta.url), "utf8"),
]);

test("institution callback endpoint is machine-authenticated, bounded and wired to the durable service", () => {
  assert.match(server, /POST.*\/api\/institution-callbacks/);
  assert.match(server, /maxBytes: 256 \* 1024/);
  assert.match(server, /request\.headers\["idempotency-key"\] !== envelope\.callbackId/);
  assert.match(server, /runtime\.receiveInstitutionCallback\(envelope\)/);
  assert.match(runtime, /new InstitutionCallbackService/);
  assert.match(runtime, /institutionCallbackService\.receive\(envelope\)/);
});
