import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { writeEvidenceFile } from "./write-evidence-file.mjs";

const IDS = ["calendar-read", "gmail-read", "approved-write", "unmapped-requester-denied"];
function fail() { throw new Error("REAL_PROVIDER_EVIDENCE_FAILED"); }
function exact(value, keys) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }

export async function recordRealProviderEvidence(resultsPath, outputPath, sourceCommit) {
  if (![resultsPath, outputPath].every((value) => typeof value === "string" && isAbsolute(value)) || !/^[a-f0-9]{40,64}$/u.test(sourceCommit)) fail();
  let inputHandle; let input;
  try {
    inputHandle = await open(resultsPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await inputHandle.stat();
    if (!info.isFile() || info.size > 1024 * 1024 || (info.mode & 0o077) !== 0 || typeof process.getuid === "function" && info.uid !== process.getuid()) fail();
    input = JSON.parse(await inputHandle.readFile({ encoding: "utf8" }));
  } catch { fail(); }
  finally { await inputHandle?.close(); }
  if (!exact(input, ["version", "sourceCommit", "verifiedAt", "checks"]) || input.version !== 1 || input.sourceCommit !== sourceCommit || !Array.isArray(input.checks) || input.checks.length !== IDS.length) fail();
  const age = Date.now() - Date.parse(input.verifiedAt);
  if (!Number.isFinite(age) || age < -300_000 || age > 86_400_000) fail();
  const seen = new Set();
  for (const check of input.checks) {
    if (!exact(check, ["id", "status"]) || !IDS.includes(check.id) || check.status !== "passed" || seen.has(check.id)) fail();
    seen.add(check.id);
  }
  const evidence = { version: 1, gate: "realProviderSmoke", status: "passed", verifiedAt: input.verifiedAt, sourceCommit, checks: IDS.map((id) => ({ id, status: "passed" })) };
  await writeEvidenceFile(outputPath, `${JSON.stringify(evidence)}\n`).catch(fail);
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    await recordRealProviderEvidence(process.env.TIDEBROKER_REAL_PROVIDER_RESULTS_PATH, process.env.TIDEBROKER_REAL_PROVIDER_EVIDENCE_PATH, sourceCommit);
    process.stdout.write("REAL_PROVIDER_EVIDENCE_WRITTEN\n");
  } catch {
    process.stderr.write("REAL_PROVIDER_EVIDENCE_FAILED\n");
    process.exitCode = 1;
  }
}
