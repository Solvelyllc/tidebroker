import type { ConnectorId } from "./policy.js";

export type ConnectorAuthorizationKind = "user-oauth" | "explicit-user-oauth" | "service-account";
export type ConnectorCapabilityAvailability = "executable" | "authorization-only";

export interface ConnectorCapabilityAction {
  readonly action: string;
  readonly mutating: boolean;
  readonly projection: "strict";
  readonly policy: "read" | "approval-required";
}

/** Provider-owned description consumed by generic onboarding and binding code. */
export interface ConnectorCapabilityDescriptor {
  readonly connectorId: ConnectorId;
  readonly capabilityId: string;
  readonly authorization: ConnectorAuthorizationKind;
  readonly permissions: readonly string[];
  readonly availability: ConnectorCapabilityAvailability;
  readonly actions: readonly ConnectorCapabilityAction[];
  readonly note?: string;
}

export interface ConnectorCapabilitySelection {
  readonly capabilityIds: readonly string[];
  readonly permissions: readonly string[];
  readonly allowedActions: readonly string[];
}

const IDENTIFIER = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,15}$/;
const ACTION = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}$/;

export function isConnectorActionId(value: unknown): value is string {
  return typeof value === "string" && value.length <= 128 && ACTION.test(value);
}

export function validateConnectorCapabilityDescriptor(value: ConnectorCapabilityDescriptor): ConnectorCapabilityDescriptor {
  if (!IDENTIFIER.test(value.capabilityId) || value.permissions.length > 256 || new Set(value.permissions).size !== value.permissions.length ||
    value.permissions.some((permission) => typeof permission !== "string" || permission.length < 1 || permission.length > 2048) ||
    value.actions.length > 128 || new Set(value.actions.map((item) => item.action)).size !== value.actions.length ||
    value.actions.some((item) => !isConnectorActionId(item.action) || item.projection !== "strict" || item.policy !== (item.mutating ? "approval-required" : "read")) ||
    value.availability !== (value.actions.length === 0 ? "authorization-only" : "executable") ||
    value.note !== undefined && (typeof value.note !== "string" || value.note.length > 4096)) throw new Error("CONNECTOR_CAPABILITY_INVALID");
  return Object.freeze({ ...value, permissions: Object.freeze([...value.permissions]), actions: Object.freeze(value.actions.map((item) => Object.freeze({ ...item }))) });
}

/** Resolves a connector-owned catalog without embedding provider rules in broker core. */
export function resolveConnectorCapabilitySelection(input: {
  readonly connectorId: ConnectorId;
  readonly selectedCapabilityIds: readonly string[];
  readonly catalog: readonly ConnectorCapabilityDescriptor[];
  readonly acceptedAuthorizationKinds: readonly ConnectorAuthorizationKind[];
  readonly baselinePermissions?: readonly string[];
  readonly canonicalizePermission?: (permission: string) => string;
}): ConnectorCapabilitySelection {
  const selected = new Set(input.selectedCapabilityIds);
  if (selected.size < 1 || selected.size !== input.selectedCapabilityIds.length) throw new Error("CONNECTOR_CAPABILITY_SELECTION_INVALID");
  const accepted = new Set(input.acceptedAuthorizationKinds);
  const catalog = input.catalog.map(validateConnectorCapabilityDescriptor);
  if (catalog.some((item) => item.connectorId !== input.connectorId) || new Set(catalog.map((item) => item.capabilityId)).size !== catalog.length) throw new Error("CONNECTOR_CAPABILITY_CATALOG_INVALID");
  const capabilities = catalog.filter((item) => selected.has(item.capabilityId));
  if (capabilities.length !== selected.size || capabilities.some((item) => !accepted.has(item.authorization))) throw new Error("CONNECTOR_CAPABILITY_SELECTION_INVALID");
  const canonicalize = input.canonicalizePermission ?? ((permission: string) => permission);
  const permissions = new Set((input.baselinePermissions ?? []).map(canonicalize));
  const actions = new Set<string>();
  for (const capability of capabilities) {
    for (const permission of capability.permissions) permissions.add(canonicalize(permission));
    for (const action of capability.actions) actions.add(action.action);
  }
  return Object.freeze({ capabilityIds: Object.freeze(capabilities.map((item) => item.capabilityId)), permissions: Object.freeze([...permissions]), allowedActions: Object.freeze([...actions]) });
}
