import type { ExecutionPrincipal } from "./identity.js";
import { principalKey } from "./identity.js";

declare const workspaceIdBrand: unique symbol;
declare const connectorIdBrand: unique symbol;
declare const accountIdBrand: unique symbol;
declare const credentialHandleBrand: unique symbol;

export type WorkspaceId = string & { readonly [workspaceIdBrand]: true };
export type ConnectorId = string & { readonly [connectorIdBrand]: true };
export type AccountId = string & { readonly [accountIdBrand]: true };

/** Opaque lookup key. It must not contain credential material. */
export type CredentialHandle = string & { readonly [credentialHandleBrand]: true };

function defineId<T extends string>(kind: string, value: string): T {
  const normalized = value.trim().normalize("NFKC").toLowerCase();
  if (!/^[a-z0-9][a-z0-9._:@/-]*$/.test(normalized) || normalized.length > 160) {
    throw new TypeError(`Invalid ${kind}.`);
  }
  return normalized as T;
}

export const defineWorkspaceId = (value: string): WorkspaceId =>
  defineId<WorkspaceId>("workspace identifier", value);
export const defineConnectorId = (value: string): ConnectorId =>
  defineId<ConnectorId>("connector identifier", value);
export const defineAccountId = (value: string): AccountId =>
  defineId<AccountId>("account identifier", value);
export const defineCredentialHandle = (value: string): CredentialHandle =>
  defineId<CredentialHandle>("credential handle", value);

export interface WorkspaceAccessRule {
  readonly workspaceId: WorkspaceId;
  readonly principal: ExecutionPrincipal;
}

export interface AccountBinding {
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly principal: ExecutionPrincipal;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
}

export interface BrokerPolicy {
  readonly workspaceAccess: readonly WorkspaceAccessRule[];
  readonly accountBindings: readonly AccountBinding[];
}

export interface ResolutionRequest {
  /** Undefined is deliberately permitted so untrusted/background runs fail closed. */
  readonly principal?: ExecutionPrincipal;
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
}

export type ResolutionFailureCode =
  | "MISSING_PRINCIPAL"
  | "WORKSPACE_ACCESS_DENIED"
  | "ACCOUNT_NOT_BOUND"
  | "AMBIGUOUS_ACCOUNT_BINDING";

export type BindingResolution =
  | { readonly ok: true; readonly binding: AccountBinding }
  | {
      readonly ok: false;
      readonly code: ResolutionFailureCode;
      readonly message: string;
    };

function snapshotPrincipal(principal: ExecutionPrincipal): ExecutionPrincipal {
  return principal.kind === "human"
    ? Object.freeze({ kind: "human", actorId: principal.actorId })
    : Object.freeze({ kind: "service", serviceId: principal.serviceId });
}

function snapshotBinding(binding: AccountBinding): AccountBinding {
  return Object.freeze({
    workspaceId: binding.workspaceId,
    connectorId: binding.connectorId,
    principal: snapshotPrincipal(binding.principal),
    accountId: binding.accountId,
    credentialHandle: binding.credentialHandle,
  });
}

/**
 * Resolves only an exact principal/workspace/connector binding. There is no
 * global, last-used, other-user, or company-account fallback path.
 */
export function resolveAccountBinding(
  policy: BrokerPolicy,
  request: ResolutionRequest,
): BindingResolution {
  if (request.principal === undefined) {
    return {
      ok: false,
      code: "MISSING_PRINCIPAL",
      message: "A trusted human or explicit service principal is required.",
    };
  }

  const requestedPrincipal = principalKey(request.principal);
  const hasWorkspaceAccess = policy.workspaceAccess.some(
    (rule) =>
      rule.workspaceId === request.workspaceId &&
      principalKey(rule.principal) === requestedPrincipal,
  );
  if (!hasWorkspaceAccess) {
    return {
      ok: false,
      code: "WORKSPACE_ACCESS_DENIED",
      message: "The principal is not authorized for the requested workspace.",
    };
  }

  const matches = policy.accountBindings.filter(
    (binding) =>
      binding.workspaceId === request.workspaceId &&
      binding.connectorId === request.connectorId &&
      principalKey(binding.principal) === requestedPrincipal,
  );

  if (matches.length === 0) {
    return {
      ok: false,
      code: "ACCOUNT_NOT_BOUND",
      message: "No exact account binding exists for this principal and workspace.",
    };
  }
  if (matches.length > 1) {
    return {
      ok: false,
      code: "AMBIGUOUS_ACCOUNT_BINDING",
      message: "Multiple account bindings exist; explicit policy repair is required.",
    };
  }

  return Object.freeze({ ok: true, binding: snapshotBinding(matches[0]) });
}
