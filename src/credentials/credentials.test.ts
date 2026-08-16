import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { defineConnectorId, defineWorkspaceId } from "../core/policy.js";
import { trustedActorFromHostContext } from "../core/identity.js";
import { bindTrustedRun } from "../core/run-binding.js";
import { defineSubjectId, ExactSubjectRegistry } from "../core/subject.js";
import { EncryptedCredentialStore, MemoryCredentialRecordBackend, StaticCredentialEncryptionKeys } from "./store.js";
import { MemoryOAuthStateBackend, OAuthCredentialCustodian } from "./oauth.js";

describe("credential and OAuth custody", () => {
  it("consumes OAuth state once and encrypts refresh material", async () => {
    const host = { requesterSenderId: "provider-subject" };
    const actor = trustedActorFromHostContext(host); if (!actor.ok) throw new Error("fixture");
    const subject = defineSubjectId("usr_0123456789abcdef");
    const workspace = defineWorkspaceId("ws_solvely");
    const bound = await bindTrustedRun({ hostContext: host, subjects: new ExactSubjectRegistry([[actor.actorId, subject]]), workspaces: { resolve: () => workspace, isMember: () => true } });
    if (!bound.ok) throw new Error("fixture");
    const backend = new MemoryCredentialRecordBackend();
    const credentials = new EncryptedCredentialStore(backend, new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(4)));
    const verifier = "a".repeat(43);
    const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
    let expectedNonce = "";
    const exchange = vi.fn(async () => ({ issuer: "https://accounts.google.com", audience: "client-public-id", nonce: expectedNonce, grantedScopes: ["calendar.readonly"], refreshToken: "refresh-secret-value", clientId: "client-public-id" }));
    const custodian = new OAuthCredentialCustodian({ connectorId: defineConnectorId("google-gog"), state: new MemoryOAuthStateBackend(), credentials, exchanger: { exchange }, expectedIssuer: "https://accounts.google.com", expectedAudience: "client-public-id", allowedScopes: ["calendar.readonly"], now: () => 100, newStateId: () => "ost_0123456789abcdef", newNonce: () => "non_0123456789abcdef" });
    const started = await custodian.begin({ binding: bound.binding, redirectTargetId: "redirect_google", scopes: ["calendar.readonly"], pkceChallenge: challenge });
    expectedNonce = started.nonce;
    const connected = await custodian.complete({ stateId: started.stateId, authorizationCode: "authorization-code", pkceVerifier: verifier });
    const encrypted = await backend.get(connected.credentialHandle);
    expect(JSON.stringify(encrypted)).not.toContain("refresh-secret-value");
    await expect(custodian.complete({ stateId: started.stateId, authorizationCode: "authorization-code", pkceVerifier: verifier })).rejects.toThrow("OAUTH_INVALID_STATE");
  });
});
