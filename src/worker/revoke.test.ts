import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import { EncryptedCredentialStore } from "../credentials/store.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { FileCredentialRecordBackend } from "../durable/credentials.js";
import { runCredentialRevocation } from "./revoke.js";
import { SecureFileCredentialEncryptionKeys } from "./secure-key-files.js";

describe("operational revocation", () => {
  it("revokes the encrypted generation and disables discovery", async () => {
    const root = await mkdtemp(join(tmpdir(), "worker-revoke-")); const keyFile = join(root, "enc.key"); await writeFile(keyFile, Buffer.alloc(32, 7), { mode: 0o600 });
    const credentialRoot = join(root, "credentials"); const metadataRoot = join(root, "metadata"); const accountRoot = join(root, "accounts"); await mkdir(accountRoot, { mode: 0o700 });
    const accountBindingsPath = join(accountRoot, "bindings.json"); const credentialHandle = defineCredentialHandle("cred_0123456789abcdef");
    const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely"); const accountId = defineAccountId("acct_0123456789abcdef");
    const store = new EncryptedCredentialStore(new FileCredentialRecordBackend(credentialRoot, metadataRoot), new SecureFileCredentialEncryptionKeys("key_1", [{ id: "key_1", path: keyFile }]));
    await store.store({ subjectId, principalKind: "human", workspaceId, connectorId: "google-gog" as never, accountId, credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: root, accountAlias: "acct_opaque123" });
    await new FileAccountBindingStore(accountBindingsPath).upsert({ subjectId, workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, accountId, credentialHandle, credentialGeneration: 1, allowedActions: ["calendar.events.list"], enabled: true });
    const config = { version: 1, socketPath: join(root, "worker.sock"), recoverStaleSocket: true, credentialRoot, metadataRoot, replayRoot: join(root, "replay"), auditRoot: join(root, "audit"), outcomeRoot: join(root, "outcomes"), accountBindingsPath, grant: { issuer: "gateway", audience: "worker", keyFile: join(root, "grant.key") }, encryption: { activeKeyId: "key_1", keys: [{ id: "key_1", keyFile }] }, googleExecution: { backend: "direct" } } as const;
    await expect(runCredentialRevocation(config, { version: 1, credentialHandle })).resolves.toEqual({ providerRevoked: true });
    await expect(store.redeem({ subjectId, workspaceId, connectorId: "google-gog" as never, credentialHandle, generation: 1 })).rejects.toMatchObject({ code: "CREDENTIAL_REVOKED" });
    await expect(new FileAccountBindingStore(accountBindingsPath).list()).resolves.toMatchObject([{ enabled: false, credentialGeneration: 2 }]);
  });
});
