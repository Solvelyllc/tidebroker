import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { FileAccountBindingStore } from "./accounts.js";

describe("durable account bindings", () => {
  it("atomically provisions and disables a single actor/workspace binding", async () => {
    const root = await mkdtemp(join(tmpdir(), "account-bindings-")); const path = join(root, "bindings.json");
    const store = new FileAccountBindingStore(path); const credentialHandle = defineCredentialHandle("cred_0123456789abcdef");
    await store.upsert({ subjectId: defineSubjectId("usr_0123456789abcdef"), workspaceId: defineWorkspaceId("ws_solvely"), accountId: defineAccountId("acct_0123456789abcdef"), credentialHandle, credentialGeneration: 1, allowedActions: ["calendar.events.list"], enabled: true });
    await expect(store.list()).resolves.toMatchObject([{ credentialHandle, credentialGeneration: 1, enabled: true }]);
    await store.disable(credentialHandle, 2);
    await expect(new FileAccountBindingStore(path).list()).resolves.toMatchObject([{ credentialHandle, credentialGeneration: 2, enabled: false }]);
  });
});
