#!/usr/bin/env node

import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

const connectorId = "google-gog";
const configPath = process.env.TIDEBROKER_WORKER_CONFIG_PATH;
const requiredActions = Object.freeze([
  "calendar.events.list",
  "gmail.messages.search",
  "gmail.messages.get",
  "drive.files.list",
  "docs.document.metadata",
  "sheets.spreadsheet.metadata",
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

async function main() {
  if (typeof configPath !== "string" || !isAbsolute(configPath) || configPath.includes("\0")) fail("WORKER_CONFIG_PATH_INVALID");
  const workerEntry = await realpath("/usr/local/bin/tidebroker-worker");
  const packageRoot = dirname(dirname(workerEntry));
  const moduleAt = (relative) => import(pathToFileURL(join(packageRoot, relative)).href);
  const [
    { loadCredentialWorkerServiceConfig },
    { FileAccountBindingStore },
    { FileCredentialRecordBackend },
    { EncryptedCredentialStore },
    { SecureFileCredentialEncryptionKeys },
    { runGogOAuthCommand },
  ] = await Promise.all([
    moduleAt("worker/bootstrap.js"),
    moduleAt("durable/accounts.js"),
    moduleAt("durable/credentials.js"),
    moduleAt("credentials/store.js"),
    moduleAt("worker/secure-key-files.js"),
    moduleAt("connectors/gog-executor.js"),
  ]);

  const config = await loadCredentialWorkerServiceConfig(configPath);
  if (config.googleExecution.backend !== "gog") fail("GOG_BACKEND_REQUIRED");
  const keys = new SecureFileCredentialEncryptionKeys(config.encryption.activeKeyId, config.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(config.credentialRoot, config.metadataRoot), keys);
  const bindings = (await new FileAccountBindingStore(config.accountBindingsPath).list())
    .filter((entry) => entry.enabled && entry.connectorId === connectorId && requiredActions.every((action) => entry.allowedActions.includes(action)));
  const candidates = [];
  for (const binding of bindings) {
    try {
      const redeemed = await credentials.redeem({
        subjectId: binding.subjectId,
        workspaceId: binding.workspaceId,
        connectorId: binding.connectorId,
        credentialHandle: binding.credentialHandle,
        generation: binding.credentialGeneration,
      });
      if (redeemed.material.kind === "oauth2") candidates.push({ binding, redeemed });
    } catch {}
  }
  candidates.sort((left, right) => right.redeemed.metadata.scopes.length - left.redeemed.metadata.scopes.length || right.binding.credentialGeneration - left.binding.credentialGeneration);
  const selected = candidates[0];
  if (!selected) fail("EXECUTABLE_GOOGLE_GRANT_NOT_FOUND");

  const gog = Object.freeze({
    executablePath: config.googleExecution.executablePath,
    executableSha256: config.googleExecution.executableSha256,
    configRoot: config.googleExecution.configRoot,
    httpsProxy: config.googleExecution.httpsProxy,
    timeoutMs: config.googleExecution.timeoutMs,
    maxOutputBytes: config.googleExecution.maxOutputBytes,
  });
  const run = async (command, argv) => await runGogOAuthCommand(gog, selected.redeemed.material, {
    command,
    argv,
    mutating: false,
    assertCredentialActive: async () => {},
    markProviderCallStarted: () => {},
  });
  const checks = [];
  const execute = async (id, operation) => {
    try {
      const value = await operation();
      checks.push({ id, status: "passed" });
      return value;
    } catch {
      checks.push({ id, status: "failed" });
      return undefined;
    }
  };

  await execute("calendar-events-shape", async () => await run("calendar.events", ["calendar", "events", "--max", "1"]));
  const messages = await execute("gmail-search-shape", async () => await run("gmail.messages.search", ["gmail", "messages", "search", "in:anywhere", "--max", "1"]));
  const message = Array.isArray(messages) ? messages.find((item) => item && typeof item === "object" && typeof item.id === "string") : undefined;
  if (message) await execute("gmail-get-shape", async () => await run("gmail.get", ["gmail", "get", message.id, "--sanitize-content"]));
  else checks.push({ id: "gmail-get-shape", status: "not-testable" });

  const files = await execute("drive-list-shape", async () => await run("drive.ls", ["drive", "ls", "--all", "--max", "100", "--fields", "files(id,mimeType),nextPageToken"]));
  const items = Array.isArray(files) ? files : [];
  const document = items.find((item) => item && typeof item === "object" && item.mimeType === "application/vnd.google-apps.document" && typeof item.id === "string");
  const spreadsheet = items.find((item) => item && typeof item === "object" && item.mimeType === "application/vnd.google-apps.spreadsheet" && typeof item.id === "string");
  if (document) await execute("docs-metadata-shape", async () => await run("docs.info", ["docs", "info", document.id]));
  else checks.push({ id: "docs-metadata-shape", status: "not-testable" });
  if (spreadsheet) await execute("sheets-metadata-shape", async () => await run("sheets.metadata", ["sheets", "metadata", spreadsheet.id]));
  else checks.push({ id: "sheets-metadata-shape", status: "not-testable" });

  const passed = checks.length === 6 && checks.every((check) => check.status === "passed");
  process.stdout.write(`${JSON.stringify({ version: 1, connectorId, gogExecutableSha256: config.googleExecution.executableSha256, status: passed ? "passed" : "failed", checks }, null, 2)}\n`);
  if (!passed) process.exitCode = 1;
}

await main().catch(() => {
  process.stderr.write("GOOGLE_EXECUTABLE_CAPABILITY_SMOKE_FAILED\n");
  process.exitCode = 1;
});
