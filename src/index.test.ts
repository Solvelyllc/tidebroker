import { describe, expect, it, vi } from "vitest";
import entry from "./index.js";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { trustedActorFromHostContext } from "./core/identity.js";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId } from "./core/policy.js";
import { defineSubjectId } from "./core/subject.js";
import { EncryptedCredentialStore, MemoryCredentialRecordBackend, StaticCredentialEncryptionKeys } from "./credentials/store.js";
import { writeSubjectMappings, writeWorkspaceMemberships } from "./durable/identity.js";
import { FileAccountBindingStore } from "./durable/accounts.js";
import { MemoryAuditSink } from "./audit/sink.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "./connectors/google-gog.js";
import { CredentialGrantVerifier } from "./worker/grant.js";
import { IsolatedCredentialWorker, MemoryGrantReplayStore } from "./worker/worker.js";
import { UnixCredentialWorkerServer } from "./worker/transport.js";
import { createAccountBindingResolveOperation } from "./worker/account-resolver.js";

function apiFor(pluginConfig: Record<string, unknown> = {}) {
  return { pluginConfig, registerTool: vi.fn(), on: vi.fn() };
}

describe("tidebroker plugin entry", () => {
  it("registers the optional status tool", () => {
    const api = apiFor();
    entry.register(api as never);
    expect(api.registerTool).toHaveBeenCalledWith(expect.any(Function), {
      name: "tidebroker_status",
      optional: true,
    });
  });

  it("omits the actor-scoped tool when trusted identity is unavailable", () => {
    const api = apiFor();
    entry.register(api as never);
    const factory = api.registerTool.mock.calls[0]?.[0];
    expect(factory({ messageChannel: "webchat" })).toBeNull();
  });

  it("binds the status tool to host context without exposing the actor id", async () => {
    const api = apiFor();
    entry.register(api as never);
    const factory = api.registerTool.mock.calls[0]?.[0];
    const tool = factory({
      requesterSenderId: "OperatorA@Example.Test",
      agentId: "company",
      messageChannel: "webchat",
    });
    const result = await tool.execute("call-1", {});

    expect(result.details).toEqual({
      authenticated: true,
      principalKind: "human",
      identitySource: "openclaw-host-context",
      agentId: "company",
      messageChannel: "webchat",
    });
    expect(JSON.stringify(result)).not.toContain("OperatorA@Example.Test");
  });

  it("activates Calendar only for a healthy trusted deployment", async () => {
    const root = await mkdtemp(join(tmpdir(), "actor-plugin-activation-"));
    const socketPath = join(root, "worker.sock"); const keyPath = join(root, "grant.key");
    const subjectPath = join(root, "subjects.json"); const membershipsPath = join(root, "memberships.json"); const accountBindingsPath = join(root, "accounts.json"); const gatewayAuditRoot = join(root, "gateway-audit");
    await writeFile(keyPath, Buffer.alloc(32, 9), { mode: 0o600 }); await mkdir(gatewayAuditRoot, { mode: 0o700 });
    const host = { requesterSenderId: "RawProviderSubject", agentId: "company", messageChannel: "webchat" };
    const actor = trustedActorFromHostContext(host); if (!actor.ok) throw new Error("fixture");
    const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely"); const accountId = defineAccountId("acct_calendar"); const credentialHandle = defineCredentialHandle("cred_calendar");
    await writeSubjectMappings(subjectPath, [[actor.actorId, subjectId]]); await writeWorkspaceMemberships(membershipsPath, [[subjectId, workspaceId]]);
    const credentials = new EncryptedCredentialStore(new MemoryCredentialRecordBackend(), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(2)));
    await credentials.store({ subjectId, principalKind: "human", workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, accountId, credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: "/worker/profile", accountAlias: "acct_opaque123" });
    await new FileAccountBindingStore(accountBindingsPath).upsert({ subjectId, workspaceId, accountId, credentialHandle, credentialGeneration: 1, allowedActions: ["calendar.events.list"], enabled: true });
    const execute = vi.fn(async ({ claims }) => {
      expect(claims.subjectId).toBe(subjectId); expect(claims.workspaceId).toBe(workspaceId);
      return { items: [{ id: "event_1" }] };
    });
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret: new Uint8Array(32).fill(9), issuer: "gateway", audience: "worker" }), credentials, replay: new MemoryGrantReplayStore(), audit: new MemoryAuditSink() }, [createAccountBindingResolveOperation(accountBindingsPath), { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: "calendar.events.list", mutating: false, execute }]);
    const server = new UnixCredentialWorkerServer({ socketPath, worker }); await server.start();
    try {
      const api = apiFor({ enabled: true, workerSocketPath: socketPath, subjectMappingsPath: subjectPath, workspaceMembershipsPath: membershipsPath, gatewayAuditRoot, workerAccountDiscovery: true, grant: { issuer: "gateway", audience: "worker", keyFile: keyPath }, agentWorkspaces: [{ agentId: "company", workspaceId }] });
      entry.register(api as never);
      const registration = api.registerTool.mock.calls.find((call) => call[1]?.name === "google_calendar_events_list");
      expect(registration).toBeDefined();
      const tool = registration?.[0](host);
      expect(Object.keys(tool.parameters.properties)).toEqual(["today", "maxResults"]);
      const result = await tool.execute("call-activation", { today: true, maxResults: 5 });
      expect(result.details).toEqual({ items: [{ id: "event_1" }] });
      expect(JSON.stringify(result)).not.toContain("RawProviderSubject");
    } finally { await server.stop(); }
  });
});
