import { describe, expect, it } from "vitest";
import { defineConnectorId } from "./policy.js";
import { resolveConnectorCapabilitySelection, validateConnectorCapabilityDescriptor } from "./capabilities.js";

const connectorId = defineConnectorId("example-provider");
const read = validateConnectorCapabilityDescriptor({ connectorId, capabilityId: "documents", authorization: "user-oauth", permissions: ["documents.read"], availability: "executable", actions: [{ action: "documents.list", mutating: false, projection: "strict", policy: "read" }] });
const authorized = validateConnectorCapabilityDescriptor({ connectorId, capabilityId: "reports", authorization: "explicit-user-oauth", permissions: ["reports.read"], availability: "authorization-only", actions: [] });
const admin = validateConnectorCapabilityDescriptor({ connectorId, capabilityId: "directory", authorization: "service-account", permissions: ["directory.read"], availability: "authorization-only", actions: [] });

describe("connector capability contracts", () => {
  it("resolves permissions and actions without provider-specific branches", () => {
    expect(resolveConnectorCapabilitySelection({ connectorId, selectedCapabilityIds: ["documents", "reports"], catalog: [read, authorized, admin], acceptedAuthorizationKinds: ["user-oauth", "explicit-user-oauth"], baselinePermissions: ["identity" ] })).toEqual({ capabilityIds: ["documents", "reports"], permissions: ["identity", "documents.read", "reports.read"], allowedActions: ["documents.list"] });
  });

  it("rejects unknown, duplicate, and incompatible authorization selections", () => {
    const base = { connectorId, catalog: [read, authorized, admin], acceptedAuthorizationKinds: ["user-oauth"] as const };
    expect(() => resolveConnectorCapabilitySelection({ ...base, selectedCapabilityIds: [] })).toThrow("CONNECTOR_CAPABILITY_SELECTION_INVALID");
    expect(() => resolveConnectorCapabilitySelection({ ...base, selectedCapabilityIds: ["documents", "documents"] })).toThrow("CONNECTOR_CAPABILITY_SELECTION_INVALID");
    expect(() => resolveConnectorCapabilitySelection({ ...base, selectedCapabilityIds: ["directory"] })).toThrow("CONNECTOR_CAPABILITY_SELECTION_INVALID");
  });

  it("requires executable capabilities to declare strict policy-bearing actions", () => {
    expect(() => validateConnectorCapabilityDescriptor({ connectorId, capabilityId: "bad", authorization: "user-oauth", permissions: [], availability: "executable", actions: [] })).toThrow("CONNECTOR_CAPABILITY_INVALID");
  });
});
