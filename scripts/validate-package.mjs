import { access, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const manifest = JSON.parse(await readFile(resolve(root, "openclaw.plugin.json"), "utf8"));
const workflowPaths = [".github/workflows/ci.yml", ".github/workflows/codeql.yml", ".github/workflows/release-artifacts.yml"];

if (packageJson.scripts?.prepublishOnly !== "npm run release:check") {
  throw new Error("public publish must enforce release evidence");
}

if (manifest.id !== "tidebroker") {
  throw new Error("manifest id must be tidebroker");
}
if (manifest.version !== packageJson.version) {
  throw new Error("manifest and package versions must match");
}
if (packageJson.private === true) {
  throw new Error("ClawHub release packages must not be marked private");
}
const packedFiles = new Set(packageJson.files ?? []);
for (const required of ["dist", "docs", "openclaw.plugin.json", "scripts/gog-safety-profile.yaml", "README.md"]) {
  if (!packedFiles.has(required)) throw new Error(`package files must include ${required}`);
}
for (const forbidden of ["src", "memory", "AGENTS.md", "SOUL.md", "IDENTITY.md", "USER.md", "MEMORY.md", "DREAMS.md"]) {
  if (packedFiles.has(forbidden)) throw new Error(`package files must exclude ${forbidden}`);
}
if (manifest.configSchema?.additionalProperties !== false) {
  throw new Error("plugin config schema must reject unknown properties");
}
if (!manifest.contracts?.tools?.includes("tidebroker_status")) {
  throw new Error("manifest must declare tidebroker_status");
}
if (!manifest.contracts?.tools?.includes("google_calendar_events_list")) {
  throw new Error("manifest must declare google_calendar_events_list");
}
for (const name of [
  "google_gmail_messages_search",
  "google_gmail_message_get",
  "google_gmail_message_send",
  "google_drive_files_list",
  "google_docs_document_metadata",
  "google_sheets_spreadsheet_metadata",
]) {
  if (!manifest.contracts?.tools?.includes(name)) throw new Error(`manifest must declare ${name}`);
}
if (packageJson.bin?.["tidebroker-worker"] !== "./dist/worker/entry.js") {
  throw new Error("package must expose the credential worker executable");
}
if (((await stat(resolve(root, "dist/worker/entry.js"))).mode & 0o111) === 0) {
  throw new Error("credential worker entrypoint must be executable");
}

for (const relativePath of ["dist/index.js", "dist/public.js", "dist/worker/entry.js"]) {
  await access(resolve(root, relativePath));
}
for (const relativePath of workflowPaths) {
  const workflow = await readFile(resolve(root, relativePath), "utf8");
  for (const match of workflow.matchAll(/uses:\s*([^\s#]+)/gu)) {
    if (!/@[a-f0-9]{40}$/u.test(match[1])) throw new Error(`workflow action must use an immutable commit SHA: ${relativePath}`);
  }
}
const releaseWorkflow = await readFile(resolve(root, ".github/workflows/release-artifacts.yml"), "utf8");
for (const forbidden of ["git verify-tag", "git verify-commit", "release-allowed-signers"]) {
  if (releaseWorkflow.includes(forbidden)) throw new Error(`release workflow must not require manual signing: ${forbidden}`);
}
for (const required of ["contents: write", "github.ref == 'refs/heads/main'", "git rev-parse origin/main", "git tag -a", "TIDEBROKER_OS_EVIDENCE_B64", "TIDEBROKER_PROVIDER_EVIDENCE_B64", "TIDEBROKER_MCP_EVIDENCE_B64", "npm run release:check", "build-release-artifacts.mjs", "sha256sum --check", "actions/attest@", "sbom-path:", "bundle-path", "ATTESTATION_SHA256SUMS", "gh release create", "gh release upload", "gh release edit"]) {
  if (!releaseWorkflow.includes(required)) throw new Error(`release workflow must enforce ${required}`);
}
const entry = await import(pathToFileURL(resolve(root, "dist/index.js")).href);
if (entry.default?.id !== manifest.id || typeof entry.default?.register !== "function") {
  throw new Error("built plugin entry does not match the manifest");
}

const packed = JSON.parse((await import("node:child_process")).execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8" }))[0];
for (const file of packed.files ?? []) {
  const name = String(file.path);
  if (/(?:^|\/)(?:vendor|test-fixtures|runtime)(?:\/|$)/iu.test(name) || /(?:^|\/)gog(?:\.exe)?$/iu.test(name) || /\.go$/iu.test(name) || /\.(?:key|pem|p12|pfx)$/iu.test(name)) {
    throw new Error(`package must not bundle gog/source/runtime material: ${name}`);
  }
}

process.stdout.write(`Plugin package ${manifest.id}@${manifest.version} is internally valid.\n`);
