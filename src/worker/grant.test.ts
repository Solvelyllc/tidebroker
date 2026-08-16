import { describe, expect, it } from "vitest";
import { defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { CredentialGrantIssuer, CredentialGrantVerifier } from "./grant.js";

const key = new Uint8Array(32).fill(7);
const base = { subjectId: defineSubjectId("usr_0123456789abcdef"), principalKind: "human" as const, workspaceId: defineWorkspaceId("ws_solvely"), connectorId: defineConnectorId("google-gog"), action: "calendar.events.list", credentialHandle: defineCredentialHandle("cred_calendar"), credentialGeneration: 3, requestId: "req_0123456789" };

describe("credential grants", () => {
  it("authenticates exact short-lived claims", () => {
    const issuer = new CredentialGrantIssuer({ secret: key, issuer: "gateway", audience: "credential-worker", now: () => 100, nonce: () => "non_0123456789" });
    const verifier = new CredentialGrantVerifier({ secret: key, issuer: "gateway", audience: "credential-worker", now: () => 101 });
    const claims = verifier.verify(issuer.issue(base), base.action);
    expect(claims).toMatchObject({ ...base, issuedAt: 100, expiresAt: 160 });
    expect(JSON.stringify(claims)).not.toContain("@example");
  });

  it("rejects tampering, wrong action, and expiry", () => {
    const issuer = new CredentialGrantIssuer({ secret: key, issuer: "gateway", audience: "worker", now: () => 100 });
    const grant = issuer.issue(base);
    const verifier = new CredentialGrantVerifier({ secret: key, issuer: "gateway", audience: "worker", now: () => 200 });
    expect(() => verifier.verify(grant, base.action)).toThrow("GRANT_EXPIRED");
    const active = new CredentialGrantVerifier({ secret: key, issuer: "gateway", audience: "worker", now: () => 101 });
    expect(() => active.verify({ ...grant, body: `${grant.body}x` }, base.action)).toThrow("GRANT_AUTHENTICATION_FAILED");
    expect(() => active.verify(grant, "gmail.search")).toThrow("GRANT_ACTION_MISMATCH");
  });
});
