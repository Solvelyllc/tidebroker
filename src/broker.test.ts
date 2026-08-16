import { describe, expect, it, vi } from "vitest";
import { MemoryAuditSink } from "./audit/index.js";
import { ActorBroker } from "./broker.js";
import { trustedActorFromHostContext } from "./core/identity.js";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "./core/policy.js";
import { bindTrustedRun } from "./core/run-binding.js";
import { defineSubjectId, ExactSubjectRegistry } from "./core/subject.js";
import { CredentialRevocationManager, EncryptedCredentialStore, MemoryCredentialRecordBackend, StaticCredentialEncryptionKeys } from "./credentials/index.js";
import { CredentialGrantIssuer, CredentialGrantVerifier, IsolatedCredentialWorker, MemoryGrantReplayStore } from "./worker/index.js";

describe("integrated broker, worker, audit, and revocation", () => {
  it("executes only the exact actor/workspace/account/action grant and denies stale generations", async () => {
    const subject = defineSubjectId("usr_0123456789abcdef");
    const workspaceId = defineWorkspaceId("ws_solvely");
    const connectorId = defineConnectorId("google-gog");
    const accountId = defineAccountId("acct_calendar");
    const credentialHandle = defineCredentialHandle("cred_calendar");
    const host = { requesterSenderId: "raw-provider-subject" };
    const actor = trustedActorFromHostContext(host); if (!actor.ok) throw new Error("fixture");
    let member = true;
    const run = await bindTrustedRun({ hostContext: host, subjects: new ExactSubjectRegistry([[actor.actorId, subject]]), workspaces: { resolve: () => workspaceId, isMember: () => member } });
    if (!run.ok) throw new Error("fixture");
    const credentials = new EncryptedCredentialStore(new MemoryCredentialRecordBackend(), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(5)));
    await credentials.store({ subjectId: subject, principalKind: "human", workspaceId, connectorId, accountId, credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: "/isolated/profile", accountAlias: "acct_opaque123" });
    const audit = new MemoryAuditSink();
    let nonce = 0; let event = 0;
    const secret = new Uint8Array(32).fill(9);
    const grants = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => `non_${++nonce}` });
    const broker = new ActorBroker({ bindings: [{ subjectId: subject, principalKind: "human", workspaceId, connectorId, accountId, credentialHandle, credentialGeneration: 1, allowedActions: ["calendar.events.list"], enabled: true }], operations: [{ connectorId, action: "calendar.events.list" }], credentials, grants, audit, newEventId: () => `evt_${++event}`, now: () => new Date("2026-08-15T00:00:00Z") });
    const execute = vi.fn(async () => ({ ok: true }));
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new MemoryGrantReplayStore(() => 101), audit, newEventId: () => `evt_${++event}`, now: () => new Date("2026-08-15T00:00:00Z") }, [{ connectorId, action: "calendar.events.list", mutating: false, execute }]);

    const authorized = await broker.authorize({ binding: run.binding, connectorId, action: "calendar.events.list", requestId: "req_1" });
    await expect(worker.execute({ ...authorized, input: { today: true } })).resolves.toEqual({ ok: true });
    expect(execute).toHaveBeenCalledOnce();
    await expect(worker.execute({ ...authorized, input: {} })).rejects.toMatchObject({ code: "WORKER_GRANT_REPLAYED" });

    const stale = await broker.authorize({ binding: run.binding, connectorId, action: "calendar.events.list", requestId: "req_2" });
    const revocation = new CredentialRevocationManager({ credentials, audit, newEventId: () => `evt_${++event}`, now: () => new Date("2026-08-15T00:00:00Z") });
    await expect(revocation.revoke(credentialHandle, "req_revoke")).resolves.toBe(2);
    await expect(worker.execute({ ...stale, input: {} })).rejects.toMatchObject({ code: "WORKER_CREDENTIAL_DENIED" });
    expect(execute).toHaveBeenCalledOnce();
    expect(JSON.stringify(audit.events())).not.toContain("raw-provider-subject");

    member = false;
    await expect(broker.authorize({ binding: run.binding, connectorId, action: "calendar.events.list", requestId: "req_3" })).rejects.toMatchObject({ code: "WORKSPACE_ACCESS_DENIED" });
  });
});
