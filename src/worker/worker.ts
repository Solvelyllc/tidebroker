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
  execute(context: { readonly claims: CredentialGrantClaims; readonly material?: CredentialMaterial; readonly assertCredentialActive: () => Promise<void>; readonly markProviderCallStarted: () => void }, input: TInput): Promise<TOutput>;
}

export interface MutationIntent { readonly requestId: string; readonly connectorId: string; readonly action: string; readonly inputDigest: string }
export type MutationOutcomeStatus = "pending" | "succeeded" | "failed" | "unknown";
export interface MutationOutcomeStore {
  /** Atomically records intent and returns false when this request already exists. */
  begin(intent: MutationIntent): Promise<boolean>;
  complete(requestId: string, status: Exclude<MutationOutcomeStatus, "pending">): Promise<void>;
}

export class MemoryMutationOutcomeStore implements MutationOutcomeStore {
  readonly #operations = new Map<string, MutationIntent & { status: MutationOutcomeStatus }>();
  async begin(intent: MutationIntent): Promise<boolean> { if (this.#operations.has(intent.requestId)) return false; this.#operations.set(intent.requestId, { ...intent, status: "pending" }); return true; }
  async complete(requestId: string, status: Exclude<MutationOutcomeStatus, "pending">): Promise<void> { const current = this.#operations.get(requestId); if (!current || current.status !== "pending") throw new Error("MUTATION_OUTCOME_INVALID"); this.#operations.set(requestId, { ...current, status }); }
  get(requestId: string): Readonly<(MutationIntent & { status: MutationOutcomeStatus })> | undefined { return this.#operations.get(requestId); }
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
  | "WORKER_CREDENTIAL_DENIED" | "WORKER_AUDIT_UNAVAILABLE" | "WORKER_OPERATION_FAILED" | "WORKER_OUTCOME_UNKNOWN";

export class CredentialWorkerError extends Error {
  constructor(readonly code: CredentialWorkerErrorCode, readonly retryable = code !== "WORKER_OUTCOME_UNKNOWN") { super(code); this.name = "CredentialWorkerError"; }
}

function operationKey(connector: string, action: string): string { return `${connector}\0${action}`; }

export class IsolatedCredentialWorker {
  readonly #operations = new Map<string, WorkerOperation>();
  constructor(readonly options: {
    verifier: CredentialGrantVerifier;
    credentials: EncryptedCredentialStore;
    replay: GrantReplayStore;
    audit: AuditSink;
    outcomes?: MutationOutcomeStore;
    newEventId?: () => string;
    now?: () => Date;
  }, operations: readonly WorkerOperation[]) {
    if (operations.some((operation) => operation.mutating) && !options.outcomes) throw new TypeError("Mutating worker operations require a durable outcome store.");
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

    const assertCredentialActive = async (): Promise<void> => {
      if (operation.requiresCredential === false) return;
      const latest = await this.options.credentials.metadata(claims.credentialHandle);
      if (!latest || latest.state !== "active" || latest.generation !== claims.credentialGeneration) throw new CredentialStoreError("CREDENTIAL_GENERATION_MISMATCH");
    };
    let material: CredentialMaterial | undefined;
    if (operation.requiresCredential !== false) {
      try {
        const lease = await this.options.credentials.redeem({ subjectId: claims.subjectId, workspaceId: claims.workspaceId, connectorId: claims.connectorId, credentialHandle: claims.credentialHandle, generation: claims.credentialGeneration });
        await assertCredentialActive();
        material = lease.material;
      } catch (error) {
        await this.#audit(claims, "denied", error instanceof CredentialStoreError ? error.code : "CREDENTIAL_DENIED");
        throw new CredentialWorkerError("WORKER_CREDENTIAL_DENIED");
      }
    }

    if (operation.mutating) {
      try {
        if (!await this.options.outcomes!.begin({ requestId: claims.requestId, connectorId: claims.connectorId, action: claims.action, inputDigest: claims.inputDigest! })) throw new Error("duplicate");
      } catch { throw new CredentialWorkerError("WORKER_OUTCOME_UNKNOWN", false); }
    }

    let result: unknown; let providerCallStarted = false;
    const markProviderCallStarted = () => { providerCallStarted = true; };
    try {
      result = await operation.execute({ claims, ...(material === undefined ? {} : { material }), assertCredentialActive, markProviderCallStarted }, request.input);
    } catch {
      if (operation.mutating) {
        try { await this.options.outcomes!.complete(claims.requestId, providerCallStarted ? "unknown" : "failed"); await this.#audit(claims, "failed", providerCallStarted ? "OPERATION_OUTCOME_UNKNOWN" : "OPERATION_FAILED"); }
        catch { throw new CredentialWorkerError("WORKER_OUTCOME_UNKNOWN", false); }
        if (providerCallStarted) throw new CredentialWorkerError("WORKER_OUTCOME_UNKNOWN", false);
      } else await this.#audit(claims, "failed", "OPERATION_FAILED");
      throw new CredentialWorkerError("WORKER_OPERATION_FAILED");
    }
    if (operation.mutating) {
      try { await this.options.outcomes!.complete(claims.requestId, "succeeded"); await this.#audit(claims, "succeeded", "OPERATION_SUCCEEDED"); }
      catch { throw new CredentialWorkerError("WORKER_OUTCOME_UNKNOWN", false); }
    } else await this.#audit(claims, "succeeded", "OPERATION_SUCCEEDED");
    return result as TOutput;
  }

  async #audit(claims: CredentialGrantClaims, outcome: "succeeded" | "denied" | "failed", reasonCode: string): Promise<void> {
    const event = buildAuditEvent({ actor: { id: claims.subjectId, kind: claims.principalKind }, workspace: claims.workspaceId, connector: claims.connectorId, action: claims.action, outcome, correlation: { requestId: claims.requestId }, reasonCode }, { newEventId: this.options.newEventId, now: this.options.now });
    try { await this.options.audit.append(event); }
    catch { throw new CredentialWorkerError("WORKER_AUDIT_UNAVAILABLE"); }
  }
}
