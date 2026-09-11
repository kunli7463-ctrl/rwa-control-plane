import { loadPinnedGroth16Adapter } from "../src/security/snarkjs-verifier.js";

const bundleDirectory = process.env.ZK_ARTIFACT_DIR;
const expectedManifestFileHash = process.env.ZK_ARTIFACT_MANIFEST_SHA256;

if (!bundleDirectory || !expectedManifestFileHash) {
  const error = new Error("ZK_ARTIFACT_DIR and ZK_ARTIFACT_MANIFEST_SHA256 are required");
  error.code = "ZK_ARTIFACT_CONFIGURATION_REQUIRED";
  throw error;
}

const adapter = await loadPinnedGroth16Adapter({ bundleDirectory, expectedManifestFileHash });
console.log(JSON.stringify({
  ok: true,
  mode: adapter.mode,
  circuitId: adapter.manifest.circuitId,
  circuitVersion: adapter.manifest.circuitVersion,
  manifestHash: adapter.manifestHash,
  verificationKeyHash: adapter.verificationKeyHash,
  publicSignalOrder: adapter.manifest.publicSignalOrder,
}, null, 2));
