import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

const GATES = { osIsolation: "TIDEBROKER_OS_EVIDENCE_PATH", realProviderSmoke: "TIDEBROKER_REAL_PROVIDER_EVIDENCE_PATH", mcpQuarantine: "TIDEBROKER_MCP_EVIDENCE_PATH" };
function fail() { throw new Error("RELEASE_EVIDENCE_SUMMARY_FAILED"); }
export async function buildReleaseEvidenceSummary(outputPath, paths, sourceCommit) {
  if (typeof outputPath !== "string" || !isAbsolute(outputPath) || !/^[a-f0-9]{40,64}$/u.test(sourceCommit)) fail();
  const summary = { version: 1, sourceCommit };
  for (const gate of Object.keys(GATES)) {
    const evidencePath = paths[gate];
    if (typeof evidencePath !== "string" || !isAbsolute(evidencePath)) fail();
    const bytes = await readFile(evidencePath).catch(fail); let evidence;
    try { evidence = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
    if (evidence.gate !== gate || evidence.status !== "passed" || evidence.sourceCommit !== sourceCommit || typeof evidence.verifiedAt !== "string") fail();
    summary[gate] = { status: "passed", verifiedAt: evidence.verifiedAt, evidencePath, evidenceSha256: createHash("sha256").update(bytes).digest("hex") };
  }
  const handle = await open(outputPath, "wx", 0o600).catch(fail);
  if (!handle) fail();
  try { await handle.writeFile(`${JSON.stringify(summary)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  await chmod(outputPath, 0o600);
  return summary;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    await buildReleaseEvidenceSummary(process.env.TIDEBROKER_RELEASE_EVIDENCE_PATH, Object.fromEntries(Object.entries(GATES).map(([gate, env]) => [gate, process.env[env]])), sourceCommit);
    process.stdout.write("RELEASE_EVIDENCE_SUMMARY_WRITTEN\n");
  } catch {
    process.stderr.write("RELEASE_EVIDENCE_SUMMARY_FAILED\n");
    process.exitCode = 1;
  }
}
