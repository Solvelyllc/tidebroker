import { humanPrincipal, servicePrincipal } from "./identity.js";
import type { ExecutionPrincipal } from "./identity.js";
import type {
  AccountBinding,
  AccountId,
  ConnectorId,
  CredentialHandle,
  WorkspaceId,
} from "./policy.js";

export type ConnectorTransport = "cli" | "mcp" | "http";
export type ConnectorPrincipalScope = "human" | "service" | "either";

export interface ConnectorExecutionContext {
  readonly principal: ExecutionPrincipal;
  readonly workspaceId: WorkspaceId;
  readonly accountId: AccountId;
  /** Passed to a credential store/worker; never expose its resolved secret. */
  readonly credentialHandle: CredentialHandle;
}

export interface ConnectorAccountStatus {
  readonly state: "connected" | "disconnected" | "expired" | "error";
  readonly label?: string;
  readonly detail?: string;
}

/**
 * Provider-neutral connector contract. Implementations may create a CLI worker,
 * requester-scoped MCP connection, or direct HTTP client from the opaque handle.
 */
export interface ActorConnector<TBinding, TConnection> {
  readonly id: ConnectorId;
  readonly transport: ConnectorTransport;
  readonly principalScope: ConnectorPrincipalScope;

  createBinding(
    context: Omit<ConnectorExecutionContext, "accountId" | "credentialHandle">,
  ): Promise<TBinding>;
  connect(context: ConnectorExecutionContext): Promise<TConnection>;
  status(context: ConnectorExecutionContext): Promise<ConnectorAccountStatus>;
  disconnect(context: ConnectorExecutionContext): Promise<void>;
}

export function executionContextFromBinding(
  binding: AccountBinding,
): ConnectorExecutionContext {
  const principal = binding.principal.kind === "human"
    ? humanPrincipal(binding.principal.actorId)
    : servicePrincipal(binding.principal.serviceId);
  return Object.freeze({
    principal,
    workspaceId: binding.workspaceId,
    accountId: binding.accountId,
    credentialHandle: binding.credentialHandle,
  });
}
