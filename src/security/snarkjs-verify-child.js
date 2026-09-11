import process from "node:process";

const MAX_REQUEST_BYTES = 5 * 1024 * 1024;
let bytes = 0;
const chunks = [];
let responded = false;

function respond(value, exitCode) {
  if (responded) return;
  responded = true;
  process.stdin.pause();
  process.stdout.write(JSON.stringify(value), () => process.exit(exitCode));
}

process.stdin.on("data", (chunk) => {
  bytes += chunk.length;
  if (bytes > MAX_REQUEST_BYTES) respond({ error: "verification request exceeds safety limit" }, 2);
  chunks.push(chunk);
});

process.stdin.on("end", async () => {
  if (responded) return;
  try {
    const { verificationKey, publicSignals, proof } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const snarkjs = await import("snarkjs");
    const groth16 = snarkjs.groth16 ?? snarkjs.default?.groth16;
    if (!groth16 || typeof groth16.verify !== "function") throw new Error("snarkjs groth16 verifier unavailable");
    const verified = await groth16.verify(verificationKey, publicSignals, proof);
    respond({ verified: verified === true }, 0);
  } catch (error) {
    respond({ error: error instanceof Error ? error.message : "unknown verifier failure" }, 2);
  }
});
