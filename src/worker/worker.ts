import { buildAuditEvent, type AuditSink } from "../audit/index.js";
import type { CredentialMaterial, EncryptedCredentialStore } from "../credentials/store.js";
import { CredentialStoreError } from "../credentials/store.js";
import type { ConnectorId } from "../core/policy.js";
import { CredentialGrantVerifier, GrantValidationError, type CredentialGrant, type CredentialGrantClaims } from "./grant.js";
import { canonicalPayloadDigest } from "../core/canonical.js";

export interface WorkerOperation<TInput = unknown, TOutput = unknown> {
  readonly connectorId: ConnectorId;
  readonly action: string;
  readonly mutating: boolean;
  readonly requiresCredential?: boolean;
  /** Executes only inside the isolated worker. Material must never be returned. */
  execute(context: { readonly claims: CredentialGrantClaims; readonly material?: CredentialMaterial }, input: TInput): Promise<TOutput>;
}

export interface GrantReplayStore {
  /** Atomically returns false if this nonce has already been claimed. */
  claim(nonce: string, expiresAt: number): Promise<boolean>;
}

export class MemoryGrantReplayStore implements GrantReplayStore {
  readonly #nonces = new Map<string, number>();
  constructor(readonly now: () => number = () => Math.floor(Date.now() / 1000)) {}
  async claim(nonce: string, expiresAt: number): Promise<boolean> {
    const now = this.now();
    for (const [key, expiry] of this.#nonces) if (expiry <= now) this.#nonces.delete(key);
    if (this.#nonces.has(nonce)) return false;
    this.#nonces.set(nonce, expiresAt);
    return true;
  }
}

export type CredentialWorkerErrorCode =
  | "WORKER_UNKNOWN_OPERATION" | "WORKER_GRANT_DENIED" | "WORKER_GRANT_REPLAYED"
  | "WORKER_CREDENTIAL_DENIED" | "WORKER_AUDIT_UNAVAILABLE" | "WORKER_OPERATION_FAILED";

export class CredentialWorkerError extends Error {
  constructor(readonly code: CredentialWorkerErrorCode) { super(code); this.name = "CredentialWorkerError"; }
}

function operationKey(connector: string, action: string): string { return `${connector}\0${action}`; }

export class IsolatedCredentialWorker {
  readonly #operations = new Map<string, WorkerOperation>();
  constructor(readonly options: {
    verifier: CredentialGrantVerifier;
    credentials: EncryptedCredentialStore;
    replay: GrantReplayStore;
    audit: AuditSink;
    newEventId?: () => string;
    now?: () => Date;
  }, operations: readonly WorkerOperation[]) {
    for (const operation of operations) {
      const key = operationKey(operation.connectorId, operation.action);
      if (this.#operations.has(key)) throw new TypeError("Duplicate worker operation.");
      this.#operations.set(key, operation);
    }
  }

  async execute<TOutput = unknown>(request: Readonly<{ grant: CredentialGrant; connectorId: ConnectorId; action: string; input: unknown }>): Promise<TOutput> {
    if (!request || typeof request !== "object" || Object.keys(request).some((field) => !["grant", "connectorId", "action", "input"].includes(field))) {
      throw new CredentialWorkerError("WORKER_GRANT_DENIED");
    }
    const operation = this.#operations.get(operationKey(request.connectorId, request.action));
    if (!operation) throw new CredentialWorkerError("WORKER_UNKNOWN_OPERATION");
    let claims: CredentialGrantClaims;
    try { claims = this.options.verifier.verify(request.grant, request.action); }
    catch (error) { if (error instanceof GrantValidationError) throw new CredentialWorkerError("WORKER_GRANT_DENIED"); throw error; }
    if (claims.connectorId !== request.connectorId) throw new CredentialWorkerError("WORKER_GRANT_DENIED");
    if (!await this.options.replay.claim(claims.nonce, claims.expiresAt)) throw new CredentialWorkerError("WORKER_GRANT_REPLAYED");
    if (operation.mutating && !await this.options.audit.ready()) throw new CredentialWorkerError("WORKER_AUDIT_UNAVAILABLE");
    if (operation.mutating && (!claims.inputDigest || claims.inputDigest !== canonicalPayloadDigest(request.input))) {
      await this.#audit(claims, "denied", "INPUT_DIGEST_MISMATCH");
      throw new CredentialWorkerError("WORKER_GRANT_DENIED");
    }

    let material: CredentialMaterial | undefined;
    if (operation.requiresCredential !== false) {
      try {
        const lease = await this.options.credentials.redeem({ subjectId: claims.subjectId, workspaceId: claims.workspaceId, connectorId: claims.connectorId, credentialHandle: claims.credentialHandle, generation: claims.credentialGeneration });
        const latest = await this.options.credentials.metadata(claims.credentialHandle);
        if (!latest || latest.state !== "active" || latest.generation !== claims.credentialGeneration) throw new CredentialStoreError("CREDENTIAL_GENERATION_MISMATCH");
        material = lease.material;
      } catch (error) {
        await this.#audit(claims, "denied", error instanceof CredentialStoreError ? error.code : "CREDENTIAL_DENIED");
        throw new CredentialWorkerError("WORKER_CREDENTIAL_DENIED");
      }
    }

    let result: unknown;
    try {
      result = await operation.execute({ claims, ...(material === undefined ? {} : { material }) }, request.input);
    } catch {
      await this.#audit(claims, "failed", "OPERATION_FAILED");
      throw new CredentialWorkerError("WORKER_OPERATION_FAILED");
    }
    await this.#audit(claims, "succeeded", "OPERATION_SUCCEEDED");
    return result as TOutput;
  }

  async #audit(claims: CredentialGrantClaims, outcome: "succeeded" | "denied" | "failed", reasonCode: string): Promise<void> {
    const event = buildAuditEvent({ actor: { id: claims.subjectId, kind: claims.principalKind }, workspace: claims.workspaceId, connector: claims.connectorId, action: claims.action, outcome, correlation: { requestId: claims.requestId }, reasonCode }, { newEventId: this.options.newEventId, now: this.options.now });
    try { await this.options.audit.append(event); }
    catch { throw new CredentialWorkerError("WORKER_AUDIT_UNAVAILABLE"); }
  }
}
