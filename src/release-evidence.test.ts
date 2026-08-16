import { createHash } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyReleaseEvidence } from "../scripts/check-release-gates.mjs";

const required = {
  osIsolation: ["worker-user-separated", "credential-files-isolated", "provider-egress-restricted"],
  realProviderSmoke: ["calendar-read", "gmail-read", "approved-write", "unmapped-requester-denied"],
  mcpQuarantine: ["schema-fingerprint-match", "schema-drift-quarantined", "unknown-tool-denied"],
} as const;
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "tidebroker-evidence-"));
  roots.push(root);
  const head = "a".repeat(40); const verifiedAt = new Date().toISOString();
  const summary: Record<string, unknown> = { version: 1, sourceCommit: head };
  for (const [gate, ids] of Object.entries(required)) {
    const content = `${JSON.stringify({ version: 1, gate, status: "passed", verifiedAt, sourceCommit: head, checks: ids.map((id) => ({ id, status: "passed" })) })}\n`;
    const evidencePath = join(root, `${gate}.json`); await writeFile(evidencePath, content, { mode: 0o600 }); await chmod(evidencePath, 0o600);
    summary[gate] = { status: "passed", verifiedAt, evidencePath, evidenceSha256: hash(content) };
  }
  const summaryPath = join(root, "summary.json"); await writeFile(summaryPath, `${JSON.stringify(summary)}\n`, { mode: 0o600 }); await chmod(summaryPath, 0o600);
  return { root, head, summary, summaryPath };
}

describe("release evidence", () => {
  it("verifies referenced owner-only evidence bound to the source commit", async () => {
    const value = await fixture();
    await expect(verifyReleaseEvidence(value.summaryPath, value.head)).resolves.toBe(true);
  });

  it("rejects a fabricated hash, modified evidence, and missing required check", async () => {
    const fabricated = await fixture();
    (fabricated.summary.osIsolation as Record<string, unknown>).evidenceSha256 = "b".repeat(64);
    await writeFile(fabricated.summaryPath, `${JSON.stringify(fabricated.summary)}\n`, { mode: 0o600 });
    await expect(verifyReleaseEvidence(fabricated.summaryPath, fabricated.head)).rejects.toThrow("RELEASE_GATES_NOT_PROVEN");

    const modified = await fixture();
    const modifiedGate = modified.summary.realProviderSmoke as Record<string, unknown>;
    await writeFile(String(modifiedGate.evidencePath), "{}\n", { mode: 0o600 });
    await expect(verifyReleaseEvidence(modified.summaryPath, modified.head)).rejects.toThrow("RELEASE_GATES_NOT_PROVEN");

    const incomplete = await fixture();
    const incompleteGate = incomplete.summary.mcpQuarantine as Record<string, unknown>;
    const content = `${JSON.stringify({ version: 1, gate: "mcpQuarantine", status: "passed", verifiedAt: incompleteGate.verifiedAt, sourceCommit: incomplete.head, checks: [{ id: "schema-fingerprint-match", status: "passed" }] })}\n`;
    await writeFile(String(incompleteGate.evidencePath), content, { mode: 0o600 }); incompleteGate.evidenceSha256 = hash(content);
    await writeFile(incomplete.summaryPath, `${JSON.stringify(incomplete.summary)}\n`, { mode: 0o600 });
    await expect(verifyReleaseEvidence(incomplete.summaryPath, incomplete.head)).rejects.toThrow("RELEASE_GATES_NOT_PROVEN");
  });
});
