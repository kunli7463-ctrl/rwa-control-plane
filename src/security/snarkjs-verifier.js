import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Groth16JoinSplitProofAdapter,
  JOIN_SPLIT_PUBLIC_SIGNAL_ORDER,
  verificationKeyHash,
} from "./proof-adapter.js";

const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_VERIFICATION_KEY_BYTES = 4 * 1024 * 1024;
const MAX_PROOF_BYTES = 64 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES = 64 * 1024;
const VERIFIER_TIMEOUT_MS = 15_000;
const verifierChildPath = fileURLToPath(new URL("./snarkjs-verify-child.js", import.meta.url));

function artifactError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw artifactError("INVALID_ARTIFACT_MANIFEST", `${label} has an unexpected field set`);
  }
}

async function confinedRegularFile(bundleDirectory, relativePath) {
  if (typeof relativePath !== "string" || relativePath.length === 0 || path.isAbsolute(relativePath)) {
    throw artifactError("INVALID_ARTIFACT_PATH", "artifact path must be a non-empty relative path");
  }
  const root = await realpath(bundleDirectory);
  let target;
  try { target = await realpath(path.resolve(root, relativePath)); }
  catch (cause) { throw artifactError("ARTIFACT_FILE_UNAVAILABLE", `artifact file is unavailable: ${relativePath}`, cause); }
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    throw artifactError("ARTIFACT_PATH_ESCAPE", "artifact path escapes the approved bundle directory");
  }
  const metadata = await stat(target);
  if (!metadata.isFile()) throw artifactError("INVALID_ARTIFACT_FILE", "artifact must be a regular file");
  return target;
}

async function readBoundedFile(filePath, maximumBytes, code, label) {
  const metadata = await stat(filePath);
  if (metadata.size > maximumBytes) {
    throw artifactError(code, `${label} exceeds the ${maximumBytes}-byte safety limit`);
  }
  return readFile(filePath);
}

function isDecimal(value) {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

function isG1Point(value) {
  return Array.isArray(value) && value.length === 3 && value.every(isDecimal);
}

function isG2Point(value) {
  return Array.isArray(value) && value.length === 3
    && value.every((coordinate) => Array.isArray(coordinate)
      && coordinate.length === 2 && coordinate.every(isDecimal));
}

function validateGroth16Proof(proof) {
  let encoded;
  try { encoded = JSON.stringify(proof); }
  catch (cause) { throw artifactError("INVALID_GROTH16_PROOF", "Groth16 proof must be serializable JSON", cause); }
  if (!encoded || Buffer.byteLength(encoded, "utf8") > MAX_PROOF_BYTES
      || !proof || typeof proof !== "object" || Array.isArray(proof)
      || JSON.stringify(Object.keys(proof).sort())
        !== JSON.stringify(["curve", "pi_a", "pi_b", "pi_c", "protocol"].sort())
      || proof.protocol !== "groth16" || proof.curve !== "bn128"
      || !isG1Point(proof.pi_a) || !isG2Point(proof.pi_b) || !isG1Point(proof.pi_c)) {
    throw artifactError("INVALID_GROTH16_PROOF", "proof must be a bounded canonical snarkjs Groth16/bn128 object");
  }
}

export class SnarkJsGroth16Verifier {
  constructor(snarkjsModule = null) {
    const groth16 = snarkjsModule?.groth16 ?? snarkjsModule?.default?.groth16 ?? null;
    if (snarkjsModule !== null && (!groth16 || typeof groth16.verify !== "function")) {
      throw artifactError("INVALID_SNARKJS_MODULE", "snarkjs module must expose groth16.verify");
    }
    this.groth16 = groth16;
  }

  async verify(verificationKey, publicSignals, proof) {
    validateGroth16Proof(proof);
    if (this.groth16) return this.groth16.verify(verificationKey, publicSignals, proof);
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [verifierChildPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "", NODE_ENV: "production" },
        windowsHide: true,
      });
      let settled = false;
      let stdout = "";
      let stderr = "";
      const finish = (operation) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        operation();
      };
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(() => reject(artifactError("SNARKJS_VERIFIER_TIMEOUT", "isolated Groth16 verifier timed out")));
      }, VERIFIER_TIMEOUT_MS);
      timer.unref();
      const collect = (current, chunk) => {
        const next = current + chunk.toString("utf8");
        if (Buffer.byteLength(next, "utf8") > MAX_VERIFIER_OUTPUT_BYTES) {
          child.kill("SIGKILL");
          finish(() => reject(artifactError("SNARKJS_VERIFIER_OUTPUT_LIMIT", "isolated verifier exceeded its output limit")));
        }
        return next;
      };
      child.stdout.on("data", (chunk) => { stdout = collect(stdout, chunk); });
      child.stderr.on("data", (chunk) => { stderr = collect(stderr, chunk); });
      child.on("error", (cause) => finish(() => reject(
        artifactError("SNARKJS_VERIFIER_PROCESS_FAILURE", "failed to start isolated Groth16 verifier", cause),
      )));
      child.stdin.on("error", (cause) => finish(() => reject(
        artifactError("SNARKJS_VERIFIER_PROCESS_FAILURE", "failed to send the isolated verification request", cause),
      )));
      child.on("close", (code) => finish(() => {
        let response;
        try { response = JSON.parse(stdout); }
        catch (cause) {
          reject(artifactError(
            "SNARKJS_VERIFIER_INVALID_RESPONSE",
            `isolated verifier returned an invalid response${stderr ? `: ${stderr.slice(0, 200)}` : ""}`,
            cause,
          ));
          return;
        }
        if (code !== 0 || response.error) {
          reject(artifactError("SNARKJS_VERIFIER_PROCESS_FAILURE", response.error ?? "isolated verifier failed"));
          return;
        }
        resolve(response.verified === true);
      }));
      child.stdin.end(JSON.stringify({ verificationKey, publicSignals, proof }));
    });
  }
}

export async function loadPinnedGroth16Adapter({
  bundleDirectory,
  expectedManifestFileHash,
  snarkjsModule = null,
}) {
  if (!/^[0-9a-f]{64}$/.test(expectedManifestFileHash ?? "")) {
    throw artifactError("EXPECTED_MANIFEST_HASH_REQUIRED", "deployment must pin the manifest file SHA-256");
  }
  const manifestPath = await confinedRegularFile(bundleDirectory, "manifest.json");
  const manifestBytes = await readBoundedFile(
    manifestPath, MAX_MANIFEST_BYTES, "ARTIFACT_MANIFEST_TOO_LARGE", "artifact manifest",
  );
  const manifestFileHash = sha256(manifestBytes);
  if (manifestFileHash !== expectedManifestFileHash) {
    throw artifactError("ARTIFACT_MANIFEST_HASH_MISMATCH", "artifact manifest does not match the deployment pin");
  }
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); }
  catch (cause) { throw artifactError("INVALID_ARTIFACT_MANIFEST", "artifact manifest is not valid JSON", cause); }
  exactKeys(manifest, ["schema", "protocol", "curve", "circuitId", "circuitVersion", "publicSignalOrder", "verificationKey"], "manifest");
  exactKeys(manifest.verificationKey, ["path", "sha256"], "manifest.verificationKey");
  if (manifest.schema !== "rwa.groth16-artifact.v1" || manifest.protocol !== "groth16"
      || manifest.curve !== "bn128" || typeof manifest.circuitId !== "string"
      || typeof manifest.circuitVersion !== "string"
      || JSON.stringify(manifest.publicSignalOrder) !== JSON.stringify(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER)
      || !/^[0-9a-f]{64}$/.test(manifest.verificationKey.sha256 ?? "")) {
    throw artifactError("INVALID_ARTIFACT_MANIFEST", "manifest identity, signal order or verification-key pin is invalid");
  }
  const verificationKeyPath = await confinedRegularFile(bundleDirectory, manifest.verificationKey.path);
  const verificationKeyBytes = await readBoundedFile(
    verificationKeyPath, MAX_VERIFICATION_KEY_BYTES, "VERIFICATION_KEY_TOO_LARGE", "verification key",
  );
  if (sha256(verificationKeyBytes) !== manifest.verificationKey.sha256) {
    throw artifactError("VERIFICATION_KEY_FILE_HASH_MISMATCH", "verification key file does not match its manifest pin");
  }
  let verificationKey;
  try { verificationKey = JSON.parse(verificationKeyBytes.toString("utf8")); }
  catch (cause) { throw artifactError("INVALID_VERIFICATION_KEY", "verification key is not valid JSON", cause); }
  if (!snarkjsModule) {
    try { await import("snarkjs"); }
    catch (cause) { throw artifactError("SNARKJS_MODULE_UNAVAILABLE", "the pinned snarkjs runtime is not installed", cause); }
  }
  return new Groth16JoinSplitProofAdapter({
    verifier: new SnarkJsGroth16Verifier(snarkjsModule),
    verificationKey,
    manifest,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey),
    artifactManifestHash: manifestFileHash,
  });
}

export function sha256FileBytes(bytes) {
  return sha256(bytes);
}
