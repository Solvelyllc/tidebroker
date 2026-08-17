import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MemoryAuditSink } from "../audit/sink.js";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { ACCOUNT_BINDING_DISCOVERY_HANDLE, ACCOUNT_BINDING_RESOLVE_ACTION, createAccountBindingResolveOperation } from "./account-resolver.js";
import { CredentialGrantIssuer, CredentialGrantVerifier } from "./grant.js";
import { IsolatedCredentialWorker, MemoryGrantReplayStore } from "./worker.js";

describe("worker-side account binding discovery", () => {
  it("returns only the exact grant-bound actor/workspace binding", async () => {
    const root = await mkdtemp(join(tmpdir(), "binding-resolver-")); const path = join(root, "accounts.json");
    const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely");
    const connectorId = defineConnectorId("google-gog");
    await new FileAccountBindingStore(path).upsert({ subjectId, workspaceId, connectorId, accountId: defineAccountId("acct_0123456789abcdef"), credentialHandle: defineCredentialHandle("cred_0123456789abcdef"), credentialGeneration: 1, allowedActions: ["calendar.events.list"], enabled: true });
    const secret = new Uint8Array(32).fill(4); const issuer = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => "non_discovery" });
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials: {} as never, replay: new MemoryGrantReplayStore(() => 101), audit: new MemoryAuditSink() }, [createAccountBindingResolveOperation(path, connectorId)]);
    const grant = issuer.issue({ subjectId, principalKind: "human", workspaceId, connectorId: "google-gog" as never, action: ACCOUNT_BINDING_RESOLVE_ACTION, credentialHandle: ACCOUNT_BINDING_DISCOVERY_HANDLE, credentialGeneration: 1, requestId: "req_discovery" });
    await expect(worker.execute({ connectorId: "google-gog" as never, action: ACCOUNT_BINDING_RESOLVE_ACTION, grant, input: {} })).resolves.toMatchObject({ subjectId, workspaceId, enabled: true });
    await expect(worker.execute({ connectorId: "google-gog" as never, action: ACCOUNT_BINDING_RESOLVE_ACTION, grant, input: {} })).rejects.toMatchObject({ code: "WORKER_GRANT_REPLAYED" });
  });
});
