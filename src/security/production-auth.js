import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

function authError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function cookieValue(header = "") {
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === "rwa_session") {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return null;
}

function safeTokenMatch(supplied, expectedHash) {
  if (!supplied || !expectedHash) return false;
  const actual = Buffer.from(sha256(supplied), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export class ProductionAuthService {
  constructor(store, {
    oidcVerifier,
    now = () => new Date(),
    ttlMs = 15 * 60 * 1000,
    maxAuthAgeMs = 12 * 60 * 60 * 1000,
    secureCookies = true,
  } = {}) {
    if (!oidcVerifier || typeof oidcVerifier.verify !== "function") {
      throw authError("OIDC_VERIFIER_REQUIRED", "production authentication requires a verified OIDC adapter");
    }
    this.store = store;
    this.oidcVerifier = oidcVerifier;
    this.now = now;
    this.ttlMs = ttlMs;
    this.maxAuthAgeMs = maxAuthAgeMs;
    this.secureCookies = secureCookies;
    this.mode = "PRODUCTION_OIDC_SESSION";
  }

  async login(request) {
    try {
      return await this.#login(request);
    } catch (error) {
      await this.store.pool.query(
        `INSERT INTO rwa.authentication_events(tenant_id,event_type,outcome,reason_code)
         VALUES ($1,'LOGIN','DENIED',$2)`,
        [request?.tenantId ?? null, error.code ?? "LOGIN_FAILED"],
      ).catch(() => {});
      throw error;
    }
  }

  async #login({ idToken, tenantId, role }) {
    if (!idToken || !tenantId || !role) throw authError("INVALID_LOGIN_REQUEST", "idToken, tenantId and role are required");
    return this.store.withSerializableTransaction(async (client) => {
      const providers = await client.query(
        `SELECT id,issuer,audience,jwks_uri,required_acr FROM rwa.identity_providers WHERE status='ACTIVE'`,
      );
      if (providers.rowCount === 0) throw authError("IDENTITY_PROVIDER_UNAVAILABLE", "no active identity provider is configured");
      const claims = await this.oidcVerifier.verify(idToken, providers.rows);
      const provider = providers.rows.find((row) => row.id === claims.providerId);
      if (!provider) throw authError("UNTRUSTED_IDENTITY_PROVIDER", "OIDC assertion was not issued by an active provider");
      this.#assertClaims(claims, provider);

      const membership = await client.query(
        `SELECT p.id AS principal_id,p.status AS principal_status,p.investor_ref,m.institution_id,m.role
         FROM rwa.principals p JOIN rwa.institution_memberships m ON m.principal_id=p.id
         WHERE p.provider_id=$1 AND p.subject=$2 AND m.tenant_id=$3 AND m.role=$4
           AND m.status='ACTIVE' AND m.effective_at<=clock_timestamp()
           AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())
         FOR UPDATE OF p,m`,
        [provider.id, claims.subject, tenantId, role],
      );
      if (membership.rowCount !== 1 || membership.rows[0].principal_status !== "ACTIVE") {
        throw authError("AUTHORIZATION_DENIED", "principal has no active membership for the requested tenant and role");
      }
      const row = membership.rows[0];
      if (role === "investor" && !row.investor_ref) {
        throw authError("INVALID_IDENTITY_BINDING", "investor membership requires a server-side investor reference");
      }
      const grants = await client.query(
        "SELECT permission FROM rwa.role_permissions WHERE role=$1 ORDER BY permission",
        [role],
      );
      const permissions = grants.rows.map(({ permission }) => permission);
      const sessionToken = randomBytes(32).toString("base64url");
      const csrfToken = randomBytes(32).toString("base64url");
      const now = this.now();
      const expiresAt = new Date(now.getTime() + this.ttlMs);
      await client.query(
        `INSERT INTO rwa.production_sessions
         (id_hash,csrf_hash,principal_id,tenant_id,role,institution_id,investor_ref,permissions,
          provider_session_id,auth_time,mfa_verified_at,issued_at,expires_at,last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$12)`,
        [sha256(sessionToken), sha256(csrfToken), row.principal_id, tenantId, role, row.institution_id,
          row.investor_ref, JSON.stringify(permissions), claims.sessionId ?? null, claims.authTime,
          claims.mfaTime ?? claims.authTime, now, expiresAt],
      );
      await this.#event(client, { principalId: row.principal_id, tenantId, providerId: provider.id,
        providerSessionId: claims.sessionId, eventType: "LOGIN", outcome: "SUCCESS" });
      return {
        identity: this.#identity(row, tenantId, permissions), csrfToken,
        cookie: this.#cookie(sessionToken, Math.floor(this.ttlMs / 1000)), expiresAt: expiresAt.toISOString(),
      };
    });
  }

  async authenticate(cookieHeader) {
    const token = cookieValue(cookieHeader);
    if (!token) throw authError("AUTHENTICATION_REQUIRED", "production session is required");
    const result = await this.store.pool.query(
      `SELECT s.*,p.status AS principal_status,m.status AS membership_status,
              m.expires_at AS membership_expires_at,m.institution_id AS membership_institution_id
       FROM rwa.production_sessions s
       JOIN rwa.principals p ON p.id=s.principal_id
       LEFT JOIN rwa.institution_memberships m ON m.principal_id=s.principal_id
        AND m.tenant_id=s.tenant_id AND m.role=s.role AND m.status='ACTIVE'
       WHERE s.id_hash=$1`,
      [sha256(token)],
    );
    if (result.rowCount !== 1) throw authError("INVALID_SESSION", "production session is invalid");
    const row = result.rows[0];
    const now = this.now();
    if (row.revoked_at || row.expires_at <= now || row.principal_status !== "ACTIVE"
        || row.membership_status !== "ACTIVE" || (row.membership_expires_at && row.membership_expires_at <= now)) {
      throw authError("SESSION_EXPIRED", "session or underlying authorization is no longer active");
    }
    await this.store.pool.query(
      "UPDATE rwa.production_sessions SET last_seen_at=clock_timestamp() WHERE id_hash=$1 AND revoked_at IS NULL",
      [row.id_hash],
    );
    const currentGrants = await this.store.pool.query(
      "SELECT permission FROM rwa.role_permissions WHERE role=$1 ORDER BY permission",
      [row.role],
    );
    return {
      sessionId: row.id_hash,
      identity: {
        principalId: row.principal_id, tenantId: row.tenant_id,
        institutionId: row.membership_institution_id, role: row.role,
        actorRef: row.investor_ref, permissions: currentGrants.rows.map(({ permission }) => permission),
      },
      csrfHash: row.csrf_hash,
    };
  }

  assertCsrf(session, suppliedToken) {
    if (!safeTokenMatch(suppliedToken, session.csrfHash)) {
      throw authError("CSRF_REJECTED", "state-changing request requires the session CSRF token");
    }
  }

  async revoke(sessionId, reason = "LOGOUT") {
    await this.store.pool.query(
      `UPDATE rwa.production_sessions SET revoked_at=clock_timestamp(),revoke_reason=$2
       WHERE id_hash=$1 AND revoked_at IS NULL`,
      [sessionId, reason],
    );
  }

  #assertClaims(claims, provider) {
    const now = this.now();
    if (!claims.signatureVerified || claims.issuer !== provider.issuer || claims.audience !== provider.audience) {
      throw authError("INVALID_OIDC_ASSERTION", "OIDC signature, issuer or audience validation failed");
    }
    if (!claims.subject || !(claims.expiresAt instanceof Date) || claims.expiresAt <= now) {
      throw authError("INVALID_OIDC_ASSERTION", "OIDC subject or expiry is invalid");
    }
    if (!(claims.authTime instanceof Date) || now.getTime() - claims.authTime.getTime() > this.maxAuthAgeMs) {
      throw authError("REAUTHENTICATION_REQUIRED", "OIDC authentication is too old");
    }
    const methods = new Set(claims.authenticationMethods ?? []);
    if (!methods.has("mfa") && !methods.has("otp") && !methods.has("hwk")) {
      throw authError("MFA_REQUIRED", "production access requires a verified second factor");
    }
    if (provider.required_acr && claims.acr !== provider.required_acr) {
      throw authError("MFA_ASSURANCE_INSUFFICIENT", "OIDC assurance level does not meet institution policy");
    }
  }

  #identity(row, tenantId, permissions) {
    return { principalId: row.principal_id, tenantId, institutionId: row.institution_id,
      role: row.role, actorRef: row.investor_ref, permissions };
  }

  #cookie(token, maxAge) {
    return `rwa_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${this.secureCookies ? "; Secure" : ""}`;
  }

  async #event(client, { principalId = null, tenantId, providerId, providerSessionId, eventType, outcome, reasonCode = null }) {
    await client.query(
      `INSERT INTO rwa.authentication_events
       (principal_id,tenant_id,event_type,outcome,reason_code,provider_id,provider_session_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [principalId, tenantId, eventType, outcome, reasonCode, providerId, providerSessionId ?? null],
    );
  }
}

export function authorizePermission(identity, permission) {
  if (!Array.isArray(identity.permissions) || !identity.permissions.includes(permission)) {
    throw authError("AUTHORIZATION_DENIED", "principal lacks the required permission");
  }
}
