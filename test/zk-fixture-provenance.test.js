import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JOIN_SPLIT_PUBLIC_SIGNAL_ORDER } from "../src/security/proof-adapter.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = path.join(root, "test/fixtures/groth16-local-only");

test("the local Groth16 vector matches its manifest and both provenance documents agree", async () => {
  const manifest = JSON.parse(await readFile(path.join(fixtures, "manifest.json"), "utf8"));
  const verificationKey = await readFile(path.join(fixtures, "verification_key.json"));
  assert.equal(manifest.verificationKey.sha256, createHash("sha256").update(verificationKey).digest("hex"));
  assert.deepEqual(manifest.publicSignalOrder, [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER]);

  // D4: the fixture notice and the candidate-circuit notice must not disagree
  // about whether the vector's circuit source is proven.
  const notice = await readFile(path.join(fixtures, "DO_NOT_DEPLOY.md"), "utf8");
  const candidate = await readFile(path.join(root, "zk-candidate/NOT_APPROVED.md"), "utf8");
  assert.match(notice, /not proven/i);
  assert.match(notice, /zk-candidate\/NOT_APPROVED\.md/);
  assert.match(candidate, /未被证明/);
  assert.match(candidate, /DO_NOT_DEPLOY\.md/);
  for (const document of [notice, candidate]) assert.doesNotMatch(document, /矛盾|contradict/i);
});
