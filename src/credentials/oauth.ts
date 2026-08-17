import { createHash } from "node:crypto";
import type { ConnectorId } from "../core/policy.js";
import { defineAccountId, defineCredentialHandle, type AccountId, type CredentialHandle } from "../core/policy.js";
import { isTrustedRunBinding, type TrustedRunBinding } from "../core/run-binding.js";
import type { SubjectId } from "../core/subject.js";
import type { WorkspaceId } from "../core/policy.js";
import { EncryptedCredentialStore } from "./store.js";

export interface OAuthStateRecord {
  readonly stateId: string;
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly redirectTargetId: string;
  readonly scopes: readonly string[];
  readonly pkceChallenge: string;
  readonly nonce: string;
  readonly expiresAt: number;
}

export interface OAuthStateBackend {
  create(record: OAuthStateRecord): Promise<void>;
  /** Must remove and return atomically. */
  consume(stateId: string): Promise<OAuthStateRecord | null>;
}

export class MemoryOAuthStateBackend implements OAuthStateBackend {
  readonly #records = new Map<string, OAuthStateRecord>();
  async create(record: OAuthStateRecord): Promise<void> {
    if (this.#records.has(record.stateId)) throw new Error("OAUTH_STATE_COLLISION");
    this.#records.set(record.stateId, record);
  }
  async consume(stateId: string): Promise<OAuthStateRecord | null> {
    const record = this.#records.get(stateId) ?? null;
    this.#records.delete(stateId);
    return record;
  }
}

export interface OAuthTokenExchangeResult {
  readonly issuer: string;
  readonly audience: string;
  readonly nonce: string;
  readonly grantedScopes: readonly string[];
  readonly refreshToken: string;
  readonly clientId: string;
  readonly clientSecret?: string;
}

export interface OAuthTokenExchanger {
  /** Runs inside the credential worker. Implementations must not log inputs or responses. */
  exchange(input: { authorizationCode: string; pkceVerifier: string; redirectTargetId: string }): Promise<OAuthTokenExchangeResult>;
}

export class OAuthCustodyError extends Error {
  constructor(readonly code: "OAUTH_INVALID_STATE" | "OAUTH_STATE_EXPIRED" | "OAUTH_PKCE_FAILED" | "OAUTH_RESPONSE_INVALID") { super(code); this.name = "OAuthCustodyError"; }
}

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SCOPE = /^[A-Za-z0-9:/._-]{1,256}$/;

export class OAuthCredentialCustodian {
  readonly #allowedScopes: ReadonlySet<string>;
  constructor(readonly options: {
    connectorId: ConnectorId;
    state: OAuthStateBackend;
    credentials: EncryptedCredentialStore;
    exchanger: OAuthTokenExchanger;
    expectedIssuer: string;
    expectedAudience: string;
    allowedScopes: readonly string[];
    now?: () => number;
    newStateId?: () => string;
    newNonce?: () => string;
    newAccountId?: () => AccountId;
    newCredentialHandle?: () => CredentialHandle;
    stateTtlSeconds?: number;
  }) {
    this.#allowedScopes = new Set(options.allowedScopes);
    const ttl = options.stateTtlSeconds ?? 300;
    if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 600) throw new TypeError("OAuth state TTL must be between 30 and 600 seconds.");
  }

  async begin(input: { binding: TrustedRunBinding; redirectTargetId: string; scopes: readonly string[]; pkceChallenge: string }): Promise<Readonly<{ stateId: string; nonce: string; expiresAt: number }>> {
    if (!isTrustedRunBinding(input.binding)) throw new OAuthCustodyError("OAUTH_INVALID_STATE");
    if (!OPAQUE_ID.test(input.redirectTargetId) || !/^[A-Za-z0-9_-]{43,128}$/.test(input.pkceChallenge)) throw new OAuthCustodyError("OAUTH_INVALID_STATE");
    const scopes = [...new Set(input.scopes)];
    if (scopes.length === 0 || scopes.some((scope) => !SCOPE.test(scope) || !this.#allowedScopes.has(scope))) throw new OAuthCustodyError("OAUTH_INVALID_STATE");
    const now = (this.options.now ?? (() => Math.floor(Date.now() / 1000)))();
    const stateId = (this.options.newStateId ?? (() => `ost_${globalThis.crypto.randomUUID().replaceAll("-", "")}`))();
    const nonce = (this.options.newNonce ?? (() => `non_${globalThis.crypto.randomUUID().replaceAll("-", "")}`))();
    const expiresAt = now + (this.options.stateTtlSeconds ?? 300);
    if (!OPAQUE_ID.test(stateId) || !OPAQUE_ID.test(nonce)) throw new OAuthCustodyError("OAUTH_INVALID_STATE");
    await this.options.state.create(Object.freeze({ stateId, subjectId: input.binding.subjectId, workspaceId: input.binding.workspaceId, connectorId: this.options.connectorId, redirectTargetId: input.redirectTargetId, scopes: Object.freeze(scopes), pkceChallenge: input.pkceChallenge, nonce, expiresAt }));
    return Object.freeze({ stateId, nonce, expiresAt });
  }

  async complete(input: { stateId: string; authorizationCode: string; pkceVerifier: string }): Promise<Readonly<{ accountId: AccountId; credentialHandle: CredentialHandle; generation: number; scopes: readonly string[] }>> {
    const record = await this.options.state.consume(input.stateId);
    if (!record) throw new OAuthCustodyError("OAUTH_INVALID_STATE");
    const now = (this.options.now ?? (() => Math.floor(Date.now() / 1000)))();
    if (record.expiresAt <= now) throw new OAuthCustodyError("OAUTH_STATE_EXPIRED");
    if (!input.authorizationCode || input.authorizationCode.includes("\0") || !/^[A-Za-z0-9._~-]{43,128}$/.test(input.pkceVerifier)) throw new OAuthCustodyError("OAUTH_RESPONSE_INVALID");
    const challenge = createHash("sha256").update(input.pkceVerifier, "ascii").digest("base64url");
    if (challenge !== record.pkceChallenge) throw new OAuthCustodyError("OAUTH_PKCE_FAILED");

    const tokens = await this.options.exchanger.exchange({ authorizationCode: input.authorizationCode, pkceVerifier: input.pkceVerifier, redirectTargetId: record.redirectTargetId });
    const granted = [...new Set(tokens.grantedScopes)];
    if (tokens.issuer !== this.options.expectedIssuer) throw new Error("OAUTH_ISSUER_MISMATCH");
    if (tokens.audience !== this.options.expectedAudience) throw new Error("OAUTH_AUDIENCE_MISMATCH");
    if (tokens.nonce !== record.nonce) throw new Error("OAUTH_NONCE_MISMATCH");
    if (!tokens.refreshToken || !tokens.clientId) throw new Error("OAUTH_CREDENTIAL_MISSING");
    if (granted.length === 0) throw new Error("OAUTH_SCOPES_EMPTY");
    if (granted.some((scope) => !record.scopes.includes(scope))) throw new Error("OAUTH_SCOPE_OVERGRANT");
    if (record.scopes.some((scope) => !granted.includes(scope))) throw new Error("OAUTH_SCOPE_MISSING");
    const accountId = (this.options.newAccountId ?? (() => defineAccountId(`acct_${globalThis.crypto.randomUUID().replaceAll("-", "")}`)))();
    const credentialHandle = (this.options.newCredentialHandle ?? (() => defineCredentialHandle(`cred_${globalThis.crypto.randomUUID().replaceAll("-", "")}`)))();
    const existing = await this.options.credentials.metadata(credentialHandle);
    const generation = existing === null ? 1 : existing.generation + 1;
    await this.options.credentials.store({ subjectId: record.subjectId, principalKind: "human", workspaceId: record.workspaceId, connectorId: record.connectorId, accountId, credentialHandle, generation, scopes: granted }, { kind: "oauth2", refreshToken: tokens.refreshToken, clientId: tokens.clientId, ...(tokens.clientSecret === undefined ? {} : { clientSecret: tokens.clientSecret }) });
    return Object.freeze({ accountId, credentialHandle, generation, scopes: Object.freeze(granted) });
  }
}
