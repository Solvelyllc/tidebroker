import { describe, expect, it, vi } from "vitest";
import { MemoryAuditSink } from "../audit/sink.js";
import { canonicalPayloadDigest } from "../core/canonical.js";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { EncryptedCredentialStore, MemoryCredentialRecordBackend, StaticCredentialEncryptionKeys } from "../credentials/store.js";
import { CredentialGrantIssuer, CredentialGrantVerifier } from "./grant.js";
import { IsolatedCredentialWorker, MemoryGrantReplayStore, MemoryMutationOutcomeStore } from "./worker.js";

describe("mutating worker grants", () => {
  it("rejects a payload changed after grant issuance", async () => {
    const secret = new Uint8Array(32).fill(4); const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely"); const connectorId = defineConnectorId("google-gog"); const credentialHandle = defineCredentialHandle("cred_calendar");
    const credentials = new EncryptedCredentialStore(new MemoryCredentialRecordBackend(), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(3)));
    await credentials.store({ subjectId, principalKind: "human", workspaceId, connectorId, accountId: defineAccountId("acct_calendar"), credentialHandle, generation: 1, scopes: ["calendar.events"] }, { kind: "oauth2", refreshToken: "refresh-canary", clientId: "client" });
    const execute = vi.fn(async () => ({ ok: true })); const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new MemoryGrantReplayStore(() => 101), audit: new MemoryAuditSink(), outcomes: new MemoryMutationOutcomeStore() }, [{ connectorId, action: "calendar.events.create", mutating: true, execute }]);
    const approved = { summary: "Approved" }; const grant = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => "nonce_write" }).issue({ subjectId, principalKind: "human", workspaceId, connectorId, action: "calendar.events.create", credentialHandle, credentialGeneration: 1, requestId: "req_write", inputDigest: canonicalPayloadDigest(approved) });
    await expect(worker.execute({ connectorId, action: "calendar.events.create", grant, input: { summary: "Tampered" } })).rejects.toMatchObject({ code: "WORKER_GRANT_DENIED" });
    expect(execute).not.toHaveBeenCalled();
  });

  it("journals provider success before audit and reports audit loss as non-retriable outcome unknown", async () => {
    const secret = new Uint8Array(32).fill(6); const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely"); const connectorId = defineConnectorId("google-gog"); const credentialHandle = defineCredentialHandle("cred_calendar");
    const credentials = new EncryptedCredentialStore(new MemoryCredentialRecordBackend(), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(7)));
    await credentials.store({ subjectId, principalKind: "human", workspaceId, connectorId, accountId: defineAccountId("acct_calendar"), credentialHandle, generation: 1, scopes: ["calendar.events"] }, { kind: "oauth2", refreshToken: "refresh-canary", clientId: "client" });
    const outcomes = new MemoryMutationOutcomeStore(); const execute = vi.fn(async () => ({ created: true }));
    const audit = { ready: () => true, append: async (event: { outcome: string }) => { if (event.outcome === "succeeded") throw new Error("synthetic audit failure"); } };
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new MemoryGrantReplayStore(() => 101), audit, outcomes }, [{ connectorId, action: "calendar.events.create", mutating: true, execute }]);
    const input = { summary: "Approved" }; let nonce = 0; const issuer = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => `nonce_${++nonce}` });
    const issue = () => issuer.issue({ subjectId, principalKind: "human", workspaceId, connectorId, action: "calendar.events.create", credentialHandle, credentialGeneration: 1, requestId: "req_outcome", inputDigest: canonicalPayloadDigest(input) });
    await expect(worker.execute({ connectorId, action: "calendar.events.create", grant: issue(), input })).rejects.toMatchObject({ code: "WORKER_OUTCOME_UNKNOWN", retryable: false });
    expect(outcomes.get("req_outcome")).toMatchObject({ status: "succeeded" }); expect(execute).toHaveBeenCalledOnce();
    await expect(worker.execute({ connectorId, action: "calendar.events.create", grant: issue(), input })).rejects.toMatchObject({ code: "WORKER_OUTCOME_UNKNOWN", retryable: false });
    expect(execute).toHaveBeenCalledOnce();

    const ambiguousOutcomes = new MemoryMutationOutcomeStore();
    const ambiguousExecute = vi.fn(async ({ markProviderCallStarted }: { markProviderCallStarted: () => void }) => { markProviderCallStarted(); throw new Error("synthetic timeout"); });
    const ambiguous = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new MemoryGrantReplayStore(() => 101), audit: new MemoryAuditSink(), outcomes: ambiguousOutcomes }, [{ connectorId, action: "calendar.events.create", mutating: true, execute: ambiguousExecute }]);
    const ambiguousGrant = issuer.issue({ subjectId, principalKind: "human", workspaceId, connectorId, action: "calendar.events.create", credentialHandle, credentialGeneration: 1, requestId: "req_ambiguous", inputDigest: canonicalPayloadDigest(input) });
    await expect(ambiguous.execute({ connectorId, action: "calendar.events.create", grant: ambiguousGrant, input })).rejects.toMatchObject({ code: "WORKER_OUTCOME_UNKNOWN", retryable: false });
    expect(ambiguousOutcomes.get("req_ambiguous")).toMatchObject({ status: "unknown" });
  });
});
