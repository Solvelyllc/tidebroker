import { createHmac, timingSafeEqual } from "node:crypto";
import type { ConnectorId, CredentialHandle, WorkspaceId } from "../core/policy.js";
import type { SubjectId } from "../core/subject.js";

export interface CredentialGrantClaims {
  readonly version: 1;
  readonly issuer: string;
  readonly audience: string;
  readonly subjectId: SubjectId;
  readonly principalKind: "human" | "service";
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly action: string;
  readonly credentialHandle: CredentialHandle;
  readonly credentialGeneration: number;
  readonly requestId: string;
  /** Required for mutating operations; binds the grant to canonical request input. */
  readonly inputDigest?: string;
  readonly nonce: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface CredentialGrant {
  /** Authenticated compact claims; transport in a protected request body only. */
  readonly body: string;
  readonly authenticator: string;
}

export type GrantFailureCode =
  | "GRANT_MALFORMED"
  | "GRANT_AUTHENTICATION_FAILED"
  | "GRANT_EXPIRED"
  | "GRANT_NOT_YET_VALID"
  | "GRANT_AUDIENCE_MISMATCH"
  | "GRANT_ACTION_MISMATCH";

export class GrantValidationError extends Error {
  constructor(readonly code: GrantFailureCode) {
    super(code);
    this.name = "GrantValidationError";
  }
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ACTION = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,15}$/;
const CLAIM_KEYS = new Set([
  "version", "issuer", "audience", "subjectId", "principalKind", "workspaceId",
  "connectorId", "action", "credentialHandle", "credentialGeneration", "requestId",
  "inputDigest", "nonce", "issuedAt", "expiresAt",
]);

function mac(secret: Uint8Array, body: string): Buffer {
  return createHmac("sha256", secret).update(body, "utf8").digest();
}

function requireSecret(secret: Uint8Array): Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 32) {
    throw new TypeError("Grant authentication key must contain at least 32 bytes.");
  }
  return new Uint8Array(secret);
}

function parseClaims(body: string): CredentialGrantClaims {
  try {
    const decoded = Buffer.from(body, "base64url").toString("utf8");
    const value: unknown = JSON.parse(decoded);
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    const record = value as Record<string, unknown>;
    if (Object.keys(record).some((key) => !CLAIM_KEYS.has(key))) throw new Error();
    if (record.version !== 1 || (record.principalKind !== "human" && record.principalKind !== "service")) throw new Error();
    for (const field of ["issuer", "audience", "subjectId", "workspaceId", "connectorId", "credentialHandle", "requestId", "nonce"] as const) {
      if (typeof record[field] !== "string" || !ID.test(record[field])) throw new Error();
    }
    if (typeof record.action !== "string" || !ACTION.test(record.action)) throw new Error();
    if (record.inputDigest !== undefined && (typeof record.inputDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(record.inputDigest))) throw new Error();
    for (const field of ["credentialGeneration", "issuedAt", "expiresAt"] as const) {
      if (!Number.isSafeInteger(record[field]) || (record[field] as number) < 0) throw new Error();
    }
    return Object.freeze(record) as unknown as CredentialGrantClaims;
  } catch {
    throw new GrantValidationError("GRANT_MALFORMED");
  }
}

export class CredentialGrantIssuer {
  readonly #secret: Uint8Array;
  readonly #issuer: string;
  readonly #audience: string;
  readonly #now: () => number;
  readonly #nonce: () => string;
  readonly #maxTtlSeconds: number;

  constructor(options: {
    secret: Uint8Array;
    issuer: string;
    audience: string;
    now?: () => number;
    nonce?: () => string;
    maxTtlSeconds?: number;
  }) {
    this.#secret = requireSecret(options.secret);
    if (!ID.test(options.issuer) || !ID.test(options.audience)) throw new TypeError("Invalid grant endpoint identifier.");
    this.#issuer = options.issuer;
    this.#audience = options.audience;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#nonce = options.nonce ?? (() => globalThis.crypto.randomUUID());
    this.#maxTtlSeconds = options.maxTtlSeconds ?? 60;
    if (!Number.isSafeInteger(this.#maxTtlSeconds) || this.#maxTtlSeconds < 1 || this.#maxTtlSeconds > 300) {
      throw new TypeError("Grant TTL must be between 1 and 300 seconds.");
    }
  }

  issue(input: Omit<CredentialGrantClaims, "version" | "issuer" | "audience" | "nonce" | "issuedAt" | "expiresAt"> & { ttlSeconds?: number }): CredentialGrant {
    const ttl = input.ttlSeconds ?? this.#maxTtlSeconds;
    if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > this.#maxTtlSeconds) throw new TypeError("Invalid grant TTL.");
    const issuedAt = this.#now();
    const { ttlSeconds: _ttl, ...claimsInput } = input;
    const claims: CredentialGrantClaims = {
      version: 1,
      issuer: this.#issuer,
      audience: this.#audience,
      ...claimsInput,
      nonce: this.#nonce(),
      issuedAt,
      expiresAt: issuedAt + ttl,
    };
    const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
    parseClaims(body);
    return Object.freeze({ body, authenticator: mac(this.#secret, body).toString("base64url") });
  }
}

export class CredentialGrantVerifier {
  readonly #secret: Uint8Array;
  readonly #issuer: string;
  readonly #audience: string;
  readonly #now: () => number;
  readonly #clockSkewSeconds: number;

  constructor(options: { secret: Uint8Array; issuer: string; audience: string; now?: () => number; clockSkewSeconds?: number }) {
    this.#secret = requireSecret(options.secret);
    this.#issuer = options.issuer;
    this.#audience = options.audience;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#clockSkewSeconds = options.clockSkewSeconds ?? 5;
  }

  verify(grant: CredentialGrant, expectedAction: string): CredentialGrantClaims {
    if (!grant || typeof grant.body !== "string" || typeof grant.authenticator !== "string" || Object.keys(grant).some((key) => key !== "body" && key !== "authenticator")) {
      throw new GrantValidationError("GRANT_MALFORMED");
    }
    const expected = mac(this.#secret, grant.body);
    let supplied: Buffer;
    try { supplied = Buffer.from(grant.authenticator, "base64url"); } catch { throw new GrantValidationError("GRANT_AUTHENTICATION_FAILED"); }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      throw new GrantValidationError("GRANT_AUTHENTICATION_FAILED");
    }
    const claims = parseClaims(grant.body);
    if (claims.issuer !== this.#issuer || claims.audience !== this.#audience) throw new GrantValidationError("GRANT_AUDIENCE_MISMATCH");
    if (claims.action !== expectedAction) throw new GrantValidationError("GRANT_ACTION_MISMATCH");
    const now = this.#now();
    if (claims.issuedAt > now + this.#clockSkewSeconds) throw new GrantValidationError("GRANT_NOT_YET_VALID");
    if (claims.expiresAt <= now || claims.expiresAt - claims.issuedAt > 300) throw new GrantValidationError("GRANT_EXPIRED");
    return claims;
  }
}
