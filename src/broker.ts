import { buildAuditEvent, type AuditSink } from "./audit/index.js";
import type { AccountId, ConnectorId, CredentialHandle, WorkspaceId } from "./core/policy.js";
import { revalidateTrustedRun, isTrustedRunBinding, type TrustedRunBinding } from "./core/run-binding.js";
import type { SubjectId } from "./core/subject.js";
import type { CredentialRecordMetadata } from "./credentials/store.js";
import { CredentialGrantIssuer, type CredentialGrant } from "./worker/grant.js";

export interface OperationalAccountBinding {
  readonly subjectId: SubjectId;
  readonly principalKind: "human" | "service";
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
  readonly credentialGeneration: number;
  readonly allowedActions: readonly string[];
  readonly enabled: boolean;
}

export interface BrokerOperationRegistration {
  readonly connectorId: ConnectorId;
  readonly action: string;
}

/** Gateway-safe registry view. Implementations must never return credential material. */
export interface CredentialMetadataReader {
  metadata(handle: CredentialHandle): Promise<CredentialRecordMetadata | null>;
}

export interface AuthorizedWorkerRequest {
  readonly grant: CredentialGrant;
  readonly connectorId: ConnectorId;
  readonly action: string;
}

export type BrokerAuthorizationCode =
  | "INVALID_RUN_BINDING" | "WORKSPACE_ACCESS_DENIED" | "OPERATION_NOT_REGISTERED"
  | "ACCOUNT_NOT_BOUND" | "AMBIGUOUS_ACCOUNT_BINDING" | "ACTION_DENIED"
  | "CREDENTIAL_UNAVAILABLE" | "AUDIT_UNAVAILABLE";

export class BrokerAuthorizationError extends Error {
  constructor(readonly code: BrokerAuthorizationCode) { super(code); this.name = "BrokerAuthorizationError"; }
}

function key(connectorId: ConnectorId, action: string): string { return `${connectorId}\0${action}`; }

/** Host-side authorizer. Workspace and subject can only enter through TrustedRunBinding. */
export class ActorBroker {
  readonly #operations: ReadonlySet<string>;
  readonly #bindings: readonly OperationalAccountBinding[];
  constructor(readonly options: {
    bindings: readonly OperationalAccountBinding[];
    operations: readonly BrokerOperationRegistration[];
    /** Optional non-secret projection. The worker remains authoritative when absent or stale. */
    credentials?: CredentialMetadataReader;
    grants: CredentialGrantIssuer;
    audit: AuditSink;
    newEventId?: () => string;
    now?: () => Date;
  }) {
    this.#operations = new Set(options.operations.map((operation) => key(operation.connectorId, operation.action)));
    this.#bindings = Object.freeze(options.bindings.map((binding) => Object.freeze({ ...binding, allowedActions: Object.freeze([...binding.allowedActions]) })));
  }

  async authorize(input: {
    binding: TrustedRunBinding;
    connectorId: ConnectorId;
    action: string;
    requestId: string;
    inputDigest?: string;
  }): Promise<AuthorizedWorkerRequest> {
    if (!isTrustedRunBinding(input.binding)) throw new BrokerAuthorizationError("INVALID_RUN_BINDING");
    if (!await revalidateTrustedRun(input.binding)) return await this.#deny(input, "WORKSPACE_ACCESS_DENIED");
    if (!this.#operations.has(key(input.connectorId, input.action))) return await this.#deny(input, "OPERATION_NOT_REGISTERED");
    const matches = this.#bindings.filter((binding) => binding.enabled && binding.principalKind === "human" && binding.subjectId === input.binding.subjectId && binding.workspaceId === input.binding.workspaceId && binding.connectorId === input.connectorId);
    if (matches.length === 0) return await this.#deny(input, "ACCOUNT_NOT_BOUND");
    if (matches.length !== 1) return await this.#deny(input, "AMBIGUOUS_ACCOUNT_BINDING");
    const account = matches[0]!;
    if (!account.allowedActions.includes(input.action)) return await this.#deny(input, "ACTION_DENIED");
    if (this.options.credentials) {
      const metadata = await this.options.credentials.metadata(account.credentialHandle);
      if (!metadata || metadata.state !== "active" || metadata.generation !== account.credentialGeneration || metadata.subjectId !== account.subjectId || metadata.principalKind !== account.principalKind || metadata.workspaceId !== account.workspaceId || metadata.connectorId !== account.connectorId || metadata.accountId !== account.accountId) {
        return await this.#deny(input, "CREDENTIAL_UNAVAILABLE");
      }
    }
    return Object.freeze({
      connectorId: input.connectorId,
      action: input.action,
      grant: this.options.grants.issue({ subjectId: input.binding.subjectId, principalKind: account.principalKind, workspaceId: input.binding.workspaceId, connectorId: input.connectorId, action: input.action, credentialHandle: account.credentialHandle, credentialGeneration: account.credentialGeneration, requestId: input.requestId, ...(input.inputDigest === undefined ? {} : { inputDigest: input.inputDigest }) }),
    });
  }

  async #deny(input: { binding: TrustedRunBinding; connectorId: ConnectorId; action: string; requestId: string }, code: BrokerAuthorizationCode): Promise<never> {
    const event = buildAuditEvent({ actor: { id: input.binding.subjectId, kind: "human" }, workspace: input.binding.workspaceId, connector: input.connectorId, action: input.action, outcome: "denied", correlation: { requestId: input.requestId }, reasonCode: code }, { newEventId: this.options.newEventId, now: this.options.now });
    try { await this.options.audit.append(event); }
    catch { throw new BrokerAuthorizationError("AUDIT_UNAVAILABLE"); }
    throw new BrokerAuthorizationError(code);
  }
}
