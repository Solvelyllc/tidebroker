import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { FileAccountBindingStore } from "./accounts.js";

describe("durable account bindings", () => {
  it("atomically provisions and disables a single actor/workspace binding", async () => {
    const root = await mkdtemp(join(tmpdir(), "account-bindings-")); const path = join(root, "bindings.json");
    const store = new FileAccountBindingStore(path); const credentialHandle = defineCredentialHandle("cred_0123456789abcdef");
    await store.upsert({ subjectId: defineSubjectId("usr_0123456789abcdef"), workspaceId: defineWorkspaceId("ws_solvely"), connectorId: defineConnectorId("example-provider"), accountId: defineAccountId("acct_0123456789abcdef"), credentialHandle, credentialGeneration: 1, allowedActions: ["calendar.events.list", "project.services.enable"], enabled: true });
    await expect(store.list()).resolves.toMatchObject([{ credentialHandle, credentialGeneration: 1, enabled: true }]);
    await store.disable(credentialHandle, 2);
    await expect(new FileAccountBindingStore(path).list()).resolves.toMatchObject([{ credentialHandle, credentialGeneration: 2, enabled: false }]);
  });

  it("keeps a connected account with no currently exposed agent actions", async () => {
    const root = await mkdtemp(join(tmpdir(), "account-bindings-scopes-only-")); const path = join(root, "bindings.json");
    const store = new FileAccountBindingStore(path);
    await store.upsert({ subjectId: defineSubjectId("usr_0123456789abcdef"), workspaceId: defineWorkspaceId("ws_solvely"), connectorId: defineConnectorId("example-provider"), accountId: defineAccountId("acct_0123456789abcdef"), credentialHandle: defineCredentialHandle("cred_0123456789abcdef"), credentialGeneration: 1, allowedActions: [], enabled: true });
    await expect(store.list()).resolves.toMatchObject([{ allowedActions: [], enabled: true }]);
  });

  it("allows one actor and workspace to bind independent providers", async () => {
    const root = await mkdtemp(join(tmpdir(), "account-bindings-multi-provider-")); const path = join(root, "bindings.json");
    const store = new FileAccountBindingStore(path); const subjectId = defineSubjectId("usr_0123456789abcdef"); const workspaceId = defineWorkspaceId("ws_solvely");
    await store.upsert({ subjectId, workspaceId, connectorId: defineConnectorId("provider-one"), accountId: defineAccountId("acct_1111111111111111"), credentialHandle: defineCredentialHandle("cred_1111111111111111"), credentialGeneration: 1, allowedActions: ["records.list"], enabled: true });
    await store.upsert({ subjectId, workspaceId, connectorId: defineConnectorId("provider-two"), accountId: defineAccountId("acct_2222222222222222"), credentialHandle: defineCredentialHandle("cred_2222222222222222"), credentialGeneration: 1, allowedActions: ["messages.list"], enabled: true });
    await expect(store.list()).resolves.toHaveLength(2);
  });

  it("migrates provider-implicit v1 files only with a caller-supplied connector", async () => {
    const root = await mkdtemp(join(tmpdir(), "account-bindings-v1-")); const path = join(root, "bindings.json");
    await writeFile(path, JSON.stringify({ version: 1, entries: [{ subjectId: "usr_0123456789abcdef", workspaceId: "ws_solvely", accountId: "acct_0123456789abcdef", credentialHandle: "cred_0123456789abcdef", credentialGeneration: 1, allowedActions: ["records.list"], enabled: true }] }), { mode: 0o600 });
    await expect(new FileAccountBindingStore(path).list()).rejects.toThrow("ACCOUNT_BINDINGS_MIGRATION_REQUIRED");
    const store = new FileAccountBindingStore(path, { legacyConnectorId: defineConnectorId("example-provider") });
    await expect(store.migrateLegacy()).resolves.toBe(true);
    await expect(store.list()).resolves.toMatchObject([{ connectorId: "example-provider" }]);
    expect(JSON.parse(await readFile(path, "utf8"))).toMatchObject({ version: 2, entries: [{ connectorId: "example-provider" }] });
  });
});
