import { describe, expect, it } from "vitest";
import { resolveActorBrokerPluginConfig } from "./config.js";

const base = {
  enabled: true,
  workerSocketPath: "/run/tidebroker/worker.sock",
  subjectMappingsPath: "/var/lib/tidebroker/subjects.json",
  workspaceMembershipsPath: "/var/lib/tidebroker/memberships.json",
  gatewayAuditRoot: "/var/lib/tidebroker/audit",
  grant: { issuer: "gateway", audience: "worker", keyFile: "/run/tidebroker/grant.key" },
  agentWorkspaces: [{ agentId: "main", workspaceId: "ws_solvely" }],
};

const account = (connectorId: string, suffix: string) => ({
  subjectId: "usr_0123456789abcdef", workspaceId: "ws_solvely", connectorId,
  accountId: `acct_${suffix}`, credentialHandle: `cred_${suffix}`,
  credentialGeneration: 1, allowedActions: ["records.list"], enabled: true,
});

describe("provider-neutral plugin account config", () => {
  it("accepts multiple connector bindings for one actor and workspace", () => {
    const config = resolveActorBrokerPluginConfig({ ...base, accounts: [account("provider-one", "1111111111111111"), account("provider-two", "2222222222222222")] });
    expect(config?.accounts.map((item) => item.connectorId)).toEqual(["provider-one", "provider-two"]);
  });

  it("rejects duplicate bindings for the same connector", () => {
    expect(() => resolveActorBrokerPluginConfig({ ...base, accounts: [account("provider-one", "1111111111111111"), account("provider-one", "2222222222222222")] })).toThrow("PLUGIN_CONFIG_INVALID");
  });
});
