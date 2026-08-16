import { describe, expect, it, vi } from "vitest";
import { trustedActorFromHostContext } from "./identity.js";
import { defineWorkspaceId } from "./policy.js";
import { bindTrustedRun, revalidateTrustedRun } from "./run-binding.js";
import { defineSubjectId, ExactSubjectRegistry } from "./subject.js";

describe("trusted run binding", () => {
  it("maps host identity to an opaque subject and resolves workspace from trusted state", async () => {
    const host = { requesterSenderId: "OperatorA@Example.Test", messageChannel: "webchat" };
    const actor = trustedActorFromHostContext(host);
    if (!actor.ok) throw new Error("fixture");
    const subject = defineSubjectId("usr_0123456789abcdef");
    const workspace = defineWorkspaceId("ws_solvely");
    const isMember = vi.fn(() => true);
    const result = await bindTrustedRun({ hostContext: host, subjects: new ExactSubjectRegistry([[actor.actorId, subject]]), workspaces: { resolve: () => workspace, isMember } });
    expect(result).toMatchObject({ ok: true, binding: { subjectId: subject, workspaceId: workspace } });
    if (!result.ok) return;
    expect(JSON.stringify(result.binding)).not.toContain("OperatorA");
    expect(await revalidateTrustedRun(result.binding)).toBe(true);
    expect(isMember).toHaveBeenCalledTimes(2);
  });

  it("fails closed for unmapped subjects and revoked membership", async () => {
    const host = { requesterSenderId: "unknown" };
    const workspaces = { resolve: () => defineWorkspaceId("ws_solvely"), isMember: () => false };
    await expect(bindTrustedRun({ hostContext: host, subjects: new ExactSubjectRegistry([]), workspaces })).resolves.toMatchObject({ ok: false, code: "SUBJECT_NOT_MAPPED" });
  });
});
