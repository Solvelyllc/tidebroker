import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { recordRealProviderEvidence } from "../scripts/record-real-provider-evidence.mjs";
import { buildReleaseEvidenceSummary } from "../scripts/build-release-evidence-summary.mjs";

const roots: string[] = [];
const sourceCommit = "a".repeat(40);
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });
async function root() { const value = await mkdtemp(join(tmpdir(), "tidebroker-collector-")); roots.push(value); return value; }
const providerChecks = ["calendar-read", "gmail-read", "approved-write", "unmapped-requester-denied"];

describe("release evidence collectors", () => {
  it("records only a complete, recent, owner-only provider result", async () => {
    const directory = await root(); const input = join(directory, "results.json"); const output = join(directory, "provider.json");
    await writeFile(input, `${JSON.stringify({ version: 1, sourceCommit, verifiedAt: new Date().toISOString(), checks: providerChecks.map((id) => ({ id, status: "passed" })) })}\n`, { mode: 0o600 });
    await recordRealProviderEvidence(input, output, sourceCommit);
    await expect(readFile(output, "utf8")).resolves.toContain('"gate":"realProviderSmoke"');
  });

  it("rejects incomplete provider results and permissive files", async () => {
    const directory = await root(); const input = join(directory, "results.json");
    await writeFile(input, `${JSON.stringify({ version: 1, sourceCommit, verifiedAt: new Date().toISOString(), checks: [{ id: "calendar-read", status: "passed" }] })}\n`, { mode: 0o600 });
    await expect(recordRealProviderEvidence(input, join(directory, "out.json"), sourceCommit)).rejects.toThrow("REAL_PROVIDER_EVIDENCE_FAILED");
    await writeFile(input, "{}\n"); await chmod(input, 0o644);
    await expect(recordRealProviderEvidence(input, join(directory, "out2.json"), sourceCommit)).rejects.toThrow("REAL_PROVIDER_EVIDENCE_FAILED");
  });

  it("rejects symlinked provider results without following them", async () => {
    const directory = await root(); const target = join(directory, "target.json"); const input = join(directory, "results.json"); const outputTarget = join(directory, "output-target.json"); const outputLink = join(directory, "provider.json");
    await writeFile(target, `${JSON.stringify({ version: 1, sourceCommit, verifiedAt: new Date().toISOString(), checks: providerChecks.map((id) => ({ id, status: "passed" })) })}\n`, { mode: 0o600 });
    await symlink(target, input);
    await expect(recordRealProviderEvidence(input, join(directory, "provider.json"), sourceCommit)).rejects.toThrow("REAL_PROVIDER_EVIDENCE_FAILED");
    await rm(input); await writeFile(input, await readFile(target), { mode: 0o600 });
    await writeFile(outputTarget, "unchanged\n", { mode: 0o600 }); await symlink(outputTarget, outputLink);
    await expect(recordRealProviderEvidence(input, outputLink, sourceCommit)).rejects.toThrow("REAL_PROVIDER_EVIDENCE_FAILED");
    await expect(readFile(outputTarget, "utf8")).resolves.toBe("unchanged\n");
  });

  it("builds a commit-bound summary from the three matching gate files", async () => {
    const directory = await root(); const verifiedAt = new Date().toISOString();
    const paths: Record<string, string> = {};
    for (const gate of ["osIsolation", "realProviderSmoke", "mcpQuarantine"]) {
      const path = join(directory, `${gate}.json`); paths[gate] = path;
      await writeFile(path, `${JSON.stringify({ version: 1, gate, status: "passed", verifiedAt, sourceCommit, checks: [] })}\n`, { mode: 0o600 });
    }
    const output = join(directory, "summary.json");
    const summary = await buildReleaseEvidenceSummary(output, paths, sourceCommit);
    expect(summary).toMatchObject({ version: 1, sourceCommit, osIsolation: { status: "passed" }, realProviderSmoke: { status: "passed" }, mcpQuarantine: { status: "passed" } });
  });

  it("rejects gate evidence bound to another commit", async () => {
    const directory = await root(); const verifiedAt = new Date().toISOString(); const paths: Record<string, string> = {};
    for (const gate of ["osIsolation", "realProviderSmoke", "mcpQuarantine"]) {
      const path = join(directory, `${gate}.json`); paths[gate] = path;
      await writeFile(path, `${JSON.stringify({ version: 1, gate, status: "passed", verifiedAt, sourceCommit: "b".repeat(40), checks: [] })}\n`, { mode: 0o600 });
    }
    await expect(buildReleaseEvidenceSummary(join(directory, "summary.json"), paths, sourceCommit)).rejects.toThrow("RELEASE_EVIDENCE_SUMMARY_FAILED");
  });
});
