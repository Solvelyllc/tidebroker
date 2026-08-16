import { describe, expect, it, vi } from "vitest";
import { MemoryAuditSink } from "../audit/index.js";
import { ActorBroker } from "../broker.js";
import { trustedActorFromHostContext } from "../core/identity.js";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId, ExactSubjectRegistry } from "../core/subject.js";
import { EncryptedCredentialStore, MemoryCredentialRecordBackend, StaticCredentialEncryptionKeys } from "../credentials/store.js";
import { CredentialGrantIssuer, CredentialGrantVerifier } from "../worker/grant.js";
import { GOOGLE_CALENDAR_EVENTS_LIST_ACTION, GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";
import { ActorScopedGoogleCalendarRuntime } from "./google-runtime.js";

describe("actor-scoped Google host runtime", () => {
  it("keeps actor/workspace/account outside model input and sends only opaque claims", async () => {
    const host = { requesterSenderId: "RawProviderSubject", messageChannel: "webchat" };
    const actor = trustedActorFromHostContext(host); if (!actor.ok) throw new Error("fixture");
    const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely");
    const credentialHandle = defineCredentialHandle("cred_calendar"); const accountId = defineAccountId("acct_calendar");
    const credentials = new EncryptedCredentialStore(new MemoryCredentialRecordBackend(), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(4)));
    await credentials.store({ subjectId, principalKind: "human", workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, accountId, credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: "/worker/profile", accountAlias: "acct_opaque123" });
    const secret = new Uint8Array(32).fill(7);
    const broker = new ActorBroker({ bindings: [{ subjectId, principalKind: "human", workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, accountId, credentialHandle, credentialGeneration: 1, allowedActions: [GOOGLE_CALENDAR_EVENTS_LIST_ACTION], enabled: true }], operations: [{ connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION }], credentials, grants: new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => "non_runtime" }), audit: new MemoryAuditSink() });
    const execute = vi.fn(async (request) => {
      const claims = new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }).verify(request.grant, request.action);
      expect(claims).toMatchObject({ subjectId, workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID });
      expect(JSON.stringify(request)).not.toContain("RawProviderSubject");
      return { items: [] };
    });
    const runtime = new ActorScopedGoogleCalendarRuntime({ subjects: new ExactSubjectRegistry([[actor.actorId, subjectId]]), workspaces: { resolve: () => workspaceId, isMember: () => true }, broker, worker: { execute } });
    await expect(runtime.listEvents(host, "req_runtime", { today: true, maxResults: 5 })).resolves.toEqual({ items: [] });
    expect(execute).toHaveBeenCalledOnce();
    await expect(runtime.listEvents(host, "req_forged", { today: true, workspaceId: "ws_other", actor: "other" })).rejects.toThrow("GOG_INPUT_INVALID");
    expect(execute).toHaveBeenCalledOnce();
  });

  it("fails closed when membership is no longer valid", async () => {
    const host = { requesterSenderId: "subject" }; const actor = trustedActorFromHostContext(host); if (!actor.ok) throw new Error("fixture");
    const execute = vi.fn();
    const runtime = new ActorScopedGoogleCalendarRuntime({ subjects: new ExactSubjectRegistry([[actor.actorId, defineSubjectId("usr_0123456789abcdef")]]), workspaces: { resolve: () => defineWorkspaceId("ws_solvely"), isMember: () => false }, broker: {} as ActorBroker, worker: { execute } });
    await expect(runtime.listEvents(host, "req_denied", {})).rejects.toMatchObject({ code: "RUN_NOT_BOUND" });
    expect(execute).not.toHaveBeenCalled();
  });
});
