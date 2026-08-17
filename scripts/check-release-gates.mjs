import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

const REQUIRED_CHECKS = Object.freeze({
  osIsolation: Object.freeze(["worker-user-separated", "credential-files-isolated", "provider-egress-restricted"]),
  realProviderSmoke: Object.freeze(["calendar-read", "gmail-read", "google-capability-shapes", "approved-write", "unmapped-requester-denied"]),
  mcpQuarantine: Object.freeze(["schema-fingerprint-match", "schema-drift-quarantined", "unknown-tool-denied"]),
});
const fail = () => { throw new Error("RELEASE_GATES_NOT_PROVEN"); };
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const timestamp = (value, now) => {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed <= now + 5 * 60 * 1000 && parsed >= now - 7 * 24 * 60 * 60 * 1000;
};

async function secureBytes(path, maxBytes) {
  if (typeof path !== "string" || !isAbsolute(path)) fail();
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(fail);
  if (!handle) fail();
  try {
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0 || typeof process.getuid === "function" && info.uid !== process.getuid() || info.size < 2 || info.size > maxBytes) fail();
    const bytes = await handle.readFile();
    if (bytes.length !== info.size) fail();
    return bytes;
  } finally {
    await handle.close();
  }
}

function parseJson(bytes) { try { return JSON.parse(bytes.toString("utf8")); } catch { fail(); } }
function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }

export async function verifyReleaseEvidence(path, head, now = Date.now()) {
  if (typeof head !== "string" || !/^[a-f0-9]{40,64}$/u.test(head)) fail();
  const summary = parseJson(await secureBytes(path, 64 * 1024));
  if (!exact(summary, ["version", "sourceCommit", "osIsolation", "realProviderSmoke", "mcpQuarantine"]) || summary.version !== 1 || summary.sourceCommit !== head) fail();

  for (const [gateName, requiredChecks] of Object.entries(REQUIRED_CHECKS)) {
    const gate = summary[gateName];
    if (!exact(gate, ["status", "verifiedAt", "evidencePath", "evidenceSha256"]) || gate.status !== "passed" || !timestamp(gate.verifiedAt, now) || !/^[a-f0-9]{64}$/u.test(gate.evidenceSha256)) fail();
    const evidenceBytes = await secureBytes(gate.evidencePath, 1024 * 1024);
    if (digest(evidenceBytes) !== gate.evidenceSha256) fail();
    const evidence = parseJson(evidenceBytes);
    if (!exact(evidence, ["version", "gate", "status", "verifiedAt", "sourceCommit", "checks"]) || evidence.version !== 1 || evidence.gate !== gateName || evidence.status !== "passed" || evidence.verifiedAt !== gate.verifiedAt || evidence.sourceCommit !== head || !Array.isArray(evidence.checks) || evidence.checks.length !== requiredChecks.length) fail();
    const checks = new Set();
    for (const check of evidence.checks) {
      if (!exact(check, ["id", "status"]) || typeof check.id !== "string" || check.status !== "passed" || checks.has(check.id)) fail();
      checks.add(check.id);
    }
    if (requiredChecks.some((id) => !checks.has(id))) fail();
  }
  return true;
}

async function main() {
  const path = process.env.TIDEBROKER_RELEASE_EVIDENCE_PATH;
  if (!path) fail();
  const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  const worktree = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  if (worktree.length !== 0) fail();
  await verifyReleaseEvidence(path, head);
  process.stdout.write("RELEASE_GATES_PROVEN\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
