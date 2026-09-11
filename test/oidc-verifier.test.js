import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { RemoteJwksOidcVerifier } from "../src/security/oidc-verifier.js";

function jwt(privateKey, header, payload) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign("sha256", Buffer.from(`${encodedHeader}.${encodedPayload}`), privateKey).toString("base64url");
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

test("OIDC verifier pins provider, algorithm, key id, signature, audience and time", async () => {
  const now = new Date("2026-08-23T12:00:00Z");
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  Object.assign(jwk, { kid: "key-1", use: "sig", alg: "RS256" });
  let fetches = 0;
  const verifier = new RemoteJwksOidcVerifier({
    now: () => now,
    fetchImpl: async () => ({ ok: true, json: async () => ({ keys: [jwk] }) }),
  });
  const providers = [{
    id: "provider-1", issuer: "https://issuer.example", audience: "rwa-control-plane",
    jwks_uri: "https://issuer.example/jwks",
  }];
  const payload = {
    iss: providers[0].issuer, aud: providers[0].audience, sub: "person-1",
    exp: nowSeconds + 300, auth_time: nowSeconds - 30, amr: ["pwd", "mfa"], acr: "urn:mfa:high",
    nonce: "server-issued-login-nonce-0001",
  };
  const token = jwt(privateKey, { alg: "RS256", kid: "key-1", typ: "JWT" }, payload);
  const result = await verifier.verify(token, providers);
  assert.equal(result.signatureVerified, true);
  assert.equal(result.providerId, "provider-1");
  assert.equal(result.subject, "person-1");
  assert.equal(result.nonce, payload.nonce);
  const { nonce: _nonce, ...withoutNonce } = payload;
  await assert.rejects(
    verifier.verify(jwt(privateKey, { alg: "RS256", kid: "key-1" }, withoutNonce), providers),
    { code: "OIDC_NONCE_REQUIRED" },
  );
  await assert.rejects(
    verifier.verify(jwt(privateKey, { alg: "RS256", kid: "key-1" }, { ...payload, aud: [providers[0].audience, "other-client"] }), providers),
    { code: "OIDC_AUTHORIZED_PARTY_MISMATCH" },
  );
  await assert.rejects(
    verifier.verify(jwt(privateKey, { alg: "RS256", kid: "key-1" }, { ...payload, azp: "other-client" }), providers),
    { code: "OIDC_AUTHORIZED_PARTY_MISMATCH" },
  );
  const multiAudience = await verifier.verify(jwt(privateKey, { alg: "RS256", kid: "key-1" },
    { ...payload, aud: [providers[0].audience, "api"], azp: providers[0].audience }), providers);
  assert.equal(multiAudience.subject, "person-1");

  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  await assert.rejects(
    verifier.verify(jwt(other, { alg: "RS256", kid: "key-1" }, payload), providers),
    { code: "INVALID_OIDC_SIGNATURE" },
  );
  await assert.rejects(
    verifier.verify(jwt(privateKey, { alg: "none", kid: "key-1" }, payload), providers),
    { code: "UNSUPPORTED_OIDC_ALGORITHM" },
  );
  await assert.rejects(
    verifier.verify(jwt(privateKey, { alg: "RS256", kid: "key-1" }, { ...payload, aud: "other" }), providers),
    { code: "UNTRUSTED_IDENTITY_PROVIDER" },
  );
});

test("OIDC verifier refuses non-HTTPS signing-key endpoints", async () => {
  const now = new Date("2026-08-23T12:00:00Z");
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const verifier = new RemoteJwksOidcVerifier({ now: () => now, fetchImpl: async () => { throw new Error("unused"); } });
  const providers = [{ id: "provider-1", issuer: "https://issuer.example", audience: "rwa",
    jwks_uri: "http://issuer.example/jwks" }];
  const token = jwt(privateKey, { alg: "RS256", kid: "key-1" }, {
    iss: "https://issuer.example", aud: "rwa", sub: "person", exp: nowSeconds + 60, auth_time: nowSeconds,
  });
  await assert.rejects(verifier.verify(token, providers), { code: "INSECURE_JWKS_URI" });
});

test("OIDC verifier rejects undersized RSA signing keys", async () => {
  const now = new Date("2026-08-23T12:00:00Z");
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const jwk = publicKey.export({ format: "jwk" });
  Object.assign(jwk, { kid: "weak-key", use: "sig", alg: "RS256" });
  const verifier = new RemoteJwksOidcVerifier({
    now: () => now,
    fetchImpl: async () => ({ ok: true, json: async () => ({ keys: [jwk] }) }),
  });
  const providers = [{ id: "provider-weak", issuer: "https://weak.example", audience: "rwa",
    jwks_uri: "https://weak.example/jwks" }];
  const token = jwt(privateKey, { alg: "RS256", kid: "weak-key" }, {
    iss: "https://weak.example", aud: "rwa", sub: "person", exp: nowSeconds + 60,
    auth_time: nowSeconds,
  });
  await assert.rejects(verifier.verify(token, providers), { code: "OIDC_SIGNING_KEY_TOO_WEAK" });
});
