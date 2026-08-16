import { readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { buildAuditEvent } from "../audit/index.js";
import { trustedActorFromHostContext } from "../core/identity.js";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { EncryptedCredentialStore, StaticCredentialEncryptionKeys } from "../credentials/store.js";
import type { OAuthStateRecord } from "../credentials/oauth.js";
import { FileAuditSink } from "./audit.js";
import { FileCredentialMetadataReader, FileCredentialRecordBackend } from "./credentials.js";
import { FileSubjectMappingStore, FileWorkspaceMembershipStore, writeSubjectMappings, writeWorkspaceMemberships } from "./identity.js";
import { FileOAuthStateBackend } from "./oauth.js";
import { FileGrantReplayStore } from "./replay.js";

describe("durable deployment adapters", () => {
  it("persists exact subject and workspace mappings in private files", async () => {
    const root = await mkdtemp(join(tmpdir(), "actor-durable-"));
    const actor = trustedActorFromHostContext({ requesterSenderId: "CaseSensitiveSubject", messageChannel: "webchat" });
    if (!actor.ok) throw new Error("fixture");
    const subject = defineSubjectId("usr_0123456789abcdef");
    const workspace = defineWorkspaceId("ws_solvely");
    const subjectPath = join(root, "subjects.json");
    const membershipPath = join(root, "memberships.json");
    await writeSubjectMappings(subjectPath, [[actor.actorId, subject]]);
    await writeWorkspaceMemberships(membershipPath, [[subject, workspace]]);
    await expect(new FileSubjectMappingStore(subjectPath).resolve(actor.actorId)).resolves.toBe(subject);
    await expect(new FileWorkspaceMembershipStore(membershipPath).isMember(subject, workspace)).resolves.toBe(true);
    expect((await stat(subjectPath)).mode & 0o077).toBe(0);
  });

  it("keeps encrypted records private and publishes only metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "credential-durable-"));
    const privateRoot = join(root, "private"); const metadataRoot = join(root, "metadata");
    const backend = new FileCredentialRecordBackend(privateRoot, metadataRoot);
    const store = new EncryptedCredentialStore(backend, new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(3)));
    const handle = defineCredentialHandle("cred_calendar");
    const metadata = { subjectId: defineSubjectId("usr_0123456789abcdef"), principalKind: "human" as const, workspaceId: defineWorkspaceId("ws_solvely"), connectorId: defineConnectorId("google-gog"), accountId: defineAccountId("acct_calendar"), credentialHandle: handle, generation: 1, scopes: ["calendar.readonly"] };
    await store.store(metadata, { kind: "oauth2", refreshToken: "synthetic-refresh-canary", clientId: "public-client" });
    const privateText = await readFile(join(privateRoot, "cred_calendar.json"), "utf8");
    const metadataText = await readFile(join(metadataRoot, "cred_calendar.json"), "utf8");
    expect(privateText).not.toContain("synthetic-refresh-canary");
    expect(metadataText).not.toContain("ciphertext");
    await expect(new FileCredentialMetadataReader(metadataRoot).metadata(handle)).resolves.toMatchObject({ generation: 1, state: "active" });
    await store.revoke(handle);
    await expect(new FileCredentialMetadataReader(metadataRoot).metadata(handle)).resolves.toMatchObject({ generation: 2, state: "revoked" });
  });

  it("atomically persists OAuth consumption, replay claims, and audit events", async () => {
    const root = await mkdtemp(join(tmpdir(), "worker-durable-"));
    const oauth = new FileOAuthStateBackend(join(root, "oauth"));
    const record = { stateId: "ost_0123456789", subjectId: defineSubjectId("usr_0123456789abcdef"), workspaceId: defineWorkspaceId("ws_solvely"), connectorId: defineConnectorId("google-gog"), redirectTargetId: "redirect_google", scopes: ["calendar.readonly"], pkceChallenge: "a".repeat(43), nonce: "non_0123456789", expiresAt: 200 } satisfies OAuthStateRecord;
    await oauth.create(record);
    await expect(new FileOAuthStateBackend(join(root, "oauth")).consume(record.stateId)).resolves.toEqual(record);
    await expect(oauth.consume(record.stateId)).resolves.toBeNull();

    const replayRoot = join(root, "replay");
    await expect(new FileGrantReplayStore(replayRoot, () => 100).claim("non_1", 200)).resolves.toBe(true);
    await expect(new FileGrantReplayStore(replayRoot, () => 101).claim("non_1", 200)).resolves.toBe(false);

    const audit = new FileAuditSink(join(root, "audit"));
    await audit.append(buildAuditEvent({ actor: { id: "usr_0123456789abcdef", kind: "human" }, workspace: "ws_solvely", connector: "google-gog", action: "calendar.events.list", outcome: "succeeded", correlation: { requestId: "req_1" }, reasonCode: "OPERATION_SUCCEEDED" }, { newEventId: () => "evt_1", now: () => new Date("2026-08-15T00:00:00Z") }));
    const lines = (await readFile(join(root, "audit", "security-audit.jsonl"), "utf8")).trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toMatchObject({ eventId: "evt_1", reasonCode: "OPERATION_SUCCEEDED" });
  });
});
