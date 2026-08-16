import { chmod, open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { McpToolQuarantine, mcpSchemaFingerprint } from "../dist/mcp/tool-quarantine.js";

function fail() { throw new Error("MCP_QUARANTINE_EVIDENCE_FAILED"); }
function head() { return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(); }

export async function collectMcpQuarantineEvidence(outputPath, sourceCommit = head(), now = new Date()) {
  if (typeof outputPath !== "string" || !isAbsolute(outputPath) || !/^[a-f0-9]{40,64}$/u.test(sourceCommit)) fail();
  const schema = Object.freeze({ type: "object", additionalProperties: false, properties: { query: { type: "string", maxLength: 100 } }, required: ["query"] });
  const quarantine = new McpToolQuarantine([{ name: "search", schemaSha256: mcpSchemaFingerprint(schema), privilege: "read", approval: "none" }]);
  const exact = quarantine.inspect([{ name: "search", inputSchema: schema, privilege: "read", approval: "none" }]);
  const drift = quarantine.inspect([{ name: "search", inputSchema: { ...schema, properties: { query: { type: "string", maxLength: 10_000 } } }, privilege: "read", approval: "none" }]);
  const unknown = quarantine.inspect([{ name: "unexpected", inputSchema: {}, privilege: "write", approval: "none" }]);
  if (exact[0]?.status !== "allowed" || drift[0]?.status !== "quarantined" || drift[0].reason !== "schema-drift" || unknown[0]?.status !== "denied" || unknown[0].reason !== "unknown-tool") fail();
  const evidence = {
    version: 1,
    gate: "mcpQuarantine",
    status: "passed",
    verifiedAt: now.toISOString(),
    sourceCommit,
    checks: ["schema-fingerprint-match", "schema-drift-quarantined", "unknown-tool-denied"].map((id) => ({ id, status: "passed" })),
  };
  const handle = await open(outputPath, "wx", 0o600).catch(fail);
  if (!handle) fail();
  try { await handle.writeFile(`${JSON.stringify(evidence)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  await chmod(outputPath, 0o600);
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await collectMcpQuarantineEvidence(process.env.TIDEBROKER_MCP_EVIDENCE_PATH);
    process.stdout.write("MCP_QUARANTINE_EVIDENCE_WRITTEN\n");
  } catch {
    process.stderr.write("MCP_QUARANTINE_EVIDENCE_FAILED\n");
    process.exitCode = 1;
  }
}
