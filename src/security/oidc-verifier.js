import { createPublicKey, verify as verifySignature, constants } from "node:crypto";

function oidcError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function decodeJson(segment, label) {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw oidcError("INVALID_OIDC_TOKEN", `OIDC ${label} is not valid base64url JSON`);
  }
}

function audienceMatches(actual, expected) {
  return Array.isArray(actual) ? actual.includes(expected) : actual === expected;
}

export class RemoteJwksOidcVerifier {
  constructor({ fetchImpl = globalThis.fetch, now = () => new Date(), cacheTtlMs = 5 * 60 * 1000 } = {}) {
    if (typeof fetchImpl !== "function") throw oidcError("OIDC_FETCH_REQUIRED", "OIDC verifier requires fetch");
    this.fetch = fetchImpl;
    this.now = now;
    this.cacheTtlMs = cacheTtlMs;
    this.cache = new Map();
  }

  async verify(idToken, providers) {
    const segments = idToken?.split(".") ?? [];
    if (segments.length !== 3 || segments.some((value) => !value)) {
      throw oidcError("INVALID_OIDC_TOKEN", "OIDC token must be a compact signed JWT");
    }
    const [encodedHeader, encodedPayload, encodedSignature] = segments;
    const header = decodeJson(encodedHeader, "header");
    const payload = decodeJson(encodedPayload, "payload");
    if (!new Set(["RS256", "PS256"]).has(header.alg) || !header.kid) {
      throw oidcError("UNSUPPORTED_OIDC_ALGORITHM", "OIDC token requires RS256 or PS256 and a key id");
    }
    const candidates = providers.filter((provider) => provider.issuer === payload.iss
      && audienceMatches(payload.aud, provider.audience));
    if (candidates.length !== 1) throw oidcError("UNTRUSTED_IDENTITY_PROVIDER", "issuer and audience do not select one active provider");
    const provider = candidates[0];
    const jwksUrl = new URL(provider.jwks_uri);
    if (jwksUrl.protocol !== "https:") throw oidcError("INSECURE_JWKS_URI", "JWKS URI must use HTTPS");
    const jwks = await this.#jwks(provider.jwks_uri);
    const keys = jwks.keys.filter((key) => key.kid === header.kid && key.kty === "RSA"
      && (!key.use || key.use === "sig") && (!key.alg || key.alg === header.alg));
    if (keys.length !== 1) throw oidcError("OIDC_SIGNING_KEY_NOT_FOUND", "JWT key id did not select one signing key");
    const key = createPublicKey({ key: keys[0], format: "jwk" });
    if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw oidcError("OIDC_SIGNING_KEY_TOO_WEAK", "OIDC RSA signing keys must be at least 2048 bits");
    }
    const options = header.alg === "PS256"
      ? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
      : key;
    const valid = verifySignature("sha256", Buffer.from(`${encodedHeader}.${encodedPayload}`), options,
      Buffer.from(encodedSignature, "base64url"));
    if (!valid) throw oidcError("INVALID_OIDC_SIGNATURE", "OIDC signature validation failed");
    const nowSeconds = Math.floor(this.now().getTime() / 1000);
    if (!Number.isInteger(payload.exp) || payload.exp <= nowSeconds
        || (payload.nbf !== undefined && (!Number.isInteger(payload.nbf) || payload.nbf > nowSeconds + 60))) {
      throw oidcError("INVALID_OIDC_TIME", "OIDC token is expired or not yet valid");
    }
    if (!payload.sub || !Number.isInteger(payload.auth_time)) {
      throw oidcError("INVALID_OIDC_CLAIMS", "OIDC subject and auth_time are required");
    }
    // OIDC Core 3.1.3.7: with several audiences, or whenever azp is present,
    // the authorized party must be this client.
    if ((Array.isArray(payload.aud) && payload.aud.length !== 1) || payload.azp !== undefined) {
      if (payload.azp !== provider.audience) {
        throw oidcError("OIDC_AUTHORIZED_PARTY_MISMATCH", "OIDC token was issued to a different authorized party");
      }
    }
    if (typeof payload.nonce !== "string" || payload.nonce.length < 16 || payload.nonce.length > 512) {
      throw oidcError("OIDC_NONCE_REQUIRED", "OIDC token must carry the login challenge nonce");
    }
    return {
      providerId: provider.id, signatureVerified: true, issuer: payload.iss,
      audience: provider.audience, subject: payload.sub, sessionId: payload.sid ?? null,
      expiresAt: new Date(payload.exp * 1000), authTime: new Date(payload.auth_time * 1000),
      mfaTime: payload.mfa_time ? new Date(payload.mfa_time * 1000) : null,
      authenticationMethods: Array.isArray(payload.amr) ? payload.amr : [], acr: payload.acr ?? null,
      nonce: payload.nonce,
    };
  }

  async #jwks(uri) {
    const cached = this.cache.get(uri);
    if (cached && cached.expiresAt > this.now()) return cached.value;
    const response = await this.fetch(uri, { headers: { accept: "application/json" }, redirect: "error" });
    if (!response.ok) throw oidcError("OIDC_JWKS_UNAVAILABLE", "identity provider signing keys are unavailable");
    const value = await response.json();
    if (!Array.isArray(value.keys)) throw oidcError("INVALID_OIDC_JWKS", "identity provider JWKS is invalid");
    this.cache.set(uri, { value, expiresAt: new Date(this.now().getTime() + this.cacheTtlMs) });
    return value;
  }
}
