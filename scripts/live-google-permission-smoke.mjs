#!/usr/bin/env node

import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { loadGogPermissionShapeContracts, validateGogPermissionShape } from "./gog-permission-shapes.mjs";

const configPath = "/etc/solvely/worker.json";
const smokeBinaryPath = "/tmp/gog-tidebroker-permission-smoke";
const connectorId = "google-gog";
const maxBytes = 2 * 1024 * 1024;
const timeoutMs = 30_000;

function structure(value, depth = 0) {
  if (value === null) return "null";
  if (Array.isArray(value)) return Object.freeze({ type: "array", sample: value.length === 0 || depth > 0 ? undefined : structure(value[0], depth + 1) });
  if (typeof value !== "object") return typeof value;
  return Object.freeze({ type: "object", keys: Object.freeze(Object.keys(value).sort().slice(0, 64)) });
}

function diagnosticClass(stderr) {
  const lower = stderr.toLowerCase();
  if (lower.includes("accessnotconfigured") || lower.includes("service_disabled") || lower.includes("api has not been used") || lower.includes("has not been used in project")) return "service_disabled";
  if (lower.includes("insufficientpermissions") || lower.includes("insufficient authentication scopes") || lower.includes("insufficient permission")) return "scope_denied";
  if (lower.includes("invalid argument") || lower.includes("invalidargument")) return "invalid_request";
  if (lower.includes("failedprecondition") || lower.includes("failed precondition")) return "failed_precondition";
  if (lower.includes("unauthenticated") || lower.includes("invalid credentials")) return "unauthenticated";
  if (lower.includes("not found") || lower.includes("notfound")) return "not_found";
  if (lower.includes("forbidden") || lower.includes("permission denied")) return "forbidden";
  if (lower.includes("connect tunnel failed") || lower.includes("proxy") || lower.includes("connection refused")) return "egress_denied";
  return "unclassified";
}

function classifyFailure(exitCode, stderr) {
  const lower = stderr.toLowerCase();
  if (exitCode === 2) return "command_contract_failed";
  if (exitCode === 3) return "permission_ok_empty";
  if (lower.includes("connect tunnel failed") || lower.includes("proxy") || lower.includes("connection refused")) return "egress_denied";
  if (lower.includes("insufficient authentication scopes") || lower.includes("insufficient permission")) return "scope_denied";
  if (lower.includes("access not configured") || lower.includes("api has not been used") || lower.includes("service disabled")) return "api_disabled";
  if (lower.includes("not found") || lower.includes("404")) return "permission_ok_not_found";
  if (lower.includes("forbidden") || lower.includes("permission denied") || lower.includes("403")) return "provider_denied";
  return "provider_failed";
}

function parseOutput(stdout) {
  if (stdout.trim() === "") return null;
  return JSON.parse(stdout);
}

async function runGog(accessToken, shapeManifest, command, argv, projection) {
  return await new Promise((resolve) => {
    const outputTransform = projection === undefined
      ? ["--results-only"]
      : ["--select", projection];
    const child = spawn(smokeBinaryPath, [...outputTransform, ...argv], {
      env: {
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        GOG_HOME: "/var/lib/solvely-worker/gog",
        GOG_ACCESS_TOKEN: accessToken,
        HTTPS_PROXY: "http://127.0.0.1:3128",
        NO_PROXY: "127.0.0.1,::1,localhost",
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let terminated = false;
    const stop = () => {
      if (terminated) return;
      terminated = true;
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    };
    const timer = setTimeout(stop, timeoutMs);
    const collect = (target) => (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) stop();
      else target.push(chunk);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.on("error", stop);
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      const out = Buffer.concat(stdout).toString("utf8");
      const err = Buffer.concat(stderr).toString("utf8");
      if (terminated || bytes > maxBytes) {
        resolve(Object.freeze({ command, status: "harness_limit" }));
        return;
      }
      if (exitCode !== 0) {
        resolve(Object.freeze({ command, status: classifyFailure(exitCode, err), exitCode, diagnostic: diagnosticClass(err) }));
        return;
      }
      try {
        const value = parseOutput(out);
        const shapeStatus = validateGogPermissionShape(shapeManifest, command, value);
        resolve(Object.freeze({ command, status: shapeStatus === "valid" ? "contract_ok" : shapeStatus === "unreviewed" ? "shape_unreviewed" : "shape_contract_failed", shape: structure(value), value }));
      } catch {
        resolve(Object.freeze({ command, status: "json_shape_failed" }));
      }
    });
  });
}

function publicResult(result) {
  return Object.freeze({ command: result.command, status: result.status, ...(result.exitCode === undefined ? {} : { exitCode: result.exitCode }), ...(result.diagnostic === undefined ? {} : { diagnostic: result.diagnostic }), ...(result.shape === undefined ? {} : { shape: result.shape }) });
}

function safeProviderReasons(value) {
  const reasons = new Set();
  const visit = (item, depth = 0) => {
    if (depth > 5 || item === null || typeof item !== "object") return;
    if (Array.isArray(item)) {
      for (const child of item.slice(0, 32)) visit(child, depth + 1);
      return;
    }
    for (const [key, child] of Object.entries(item)) {
      if (["reason", "status"].includes(key) && typeof child === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(child)) reasons.add(child);
      else if (["error", "errors", "details"].includes(key)) visit(child, depth + 1);
    }
  };
  visit(value);
  return Object.freeze([...reasons].sort());
}

async function directProbe(accessToken, name, url, options = {}) {
  try {
    const response = await fetch(url, {
      method: options.method ?? "GET",
      headers: { authorization: `Bearer ${accessToken}`, ...(options.body === undefined ? {} : { "content-type": "application/json" }) },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const body = await response.text();
    if (Buffer.byteLength(body) > maxBytes) return Object.freeze({ command: name, status: "harness_limit" });
    let value = null;
    try { value = body === "" ? null : JSON.parse(body); } catch { return Object.freeze({ command: name, status: "json_shape_failed", httpStatus: response.status }); }
    if (!response.ok) return Object.freeze({ command: name, status: "provider_failed", httpStatus: response.status, reasons: safeProviderReasons(value) });
    return Object.freeze({ command: name, status: "permission_ok", httpStatus: response.status, shape: structure(value) });
  } catch {
    return Object.freeze({ command: name, status: "network_failed" });
  }
}

async function main() {
  const workerEntry = await realpath("/usr/local/bin/tidebroker-worker");
  const packageRoot = dirname(dirname(workerEntry));
  const moduleAt = (relative) => import(pathToFileURL(join(packageRoot, relative)).href);
  const [{ loadCredentialWorkerServiceConfig }, { FileAccountBindingStore }, { FileCredentialRecordBackend }, { EncryptedCredentialStore }, { SecureFileCredentialEncryptionKeys }, { googleAccessToken }] = await Promise.all([
    moduleAt("worker/bootstrap.js"),
    moduleAt("durable/accounts.js"),
    moduleAt("durable/credentials.js"),
    moduleAt("credentials/store.js"),
    moduleAt("worker/secure-key-files.js"),
    moduleAt("connectors/google-oauth.js"),
  ]);

  const binaryHandle = await open(smokeBinaryPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const binary = await binaryHandle.stat();
    if (!binary.isFile() || binary.uid !== process.getuid() || (binary.mode & 0o111) === 0 || (binary.mode & 0o022) !== 0) throw new Error("SMOKE_BINARY_INVALID");
  } finally {
    await binaryHandle.close();
  }

  const config = await loadCredentialWorkerServiceConfig(configPath);
  const keys = new SecureFileCredentialEncryptionKeys(config.encryption.activeKeyId, config.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(config.credentialRoot, config.metadataRoot), keys);
  const bindings = (await new FileAccountBindingStore(config.accountBindingsPath).list()).filter((entry) => entry.enabled && entry.connectorId === connectorId);
  const candidates = [];
  for (const binding of bindings) {
    try {
      const redeemed = await credentials.redeem({ subjectId: binding.subjectId, workspaceId: binding.workspaceId, connectorId: binding.connectorId, credentialHandle: binding.credentialHandle, generation: binding.credentialGeneration });
      if (redeemed.material.kind === "oauth2") candidates.push({ binding, redeemed });
    } catch {}
  }
  candidates.sort((left, right) => right.redeemed.metadata.scopes.length - left.redeemed.metadata.scopes.length || right.binding.credentialGeneration - left.binding.credentialGeneration);
  const selected = candidates[0];
  if (!selected || selected.redeemed.metadata.scopes.length < 20) throw new Error("FULL_GOOGLE_GRANT_NOT_FOUND");
  const accessToken = await googleAccessToken(selected.redeemed.material);
  const shapeManifest = await loadGogPermissionShapeContracts(new URL("./gog-permission-shapes-v0.37.0.json", import.meta.url));

  const directTests = [
    ["chat", "https://chat.googleapis.com/v1/spaces?pageSize=1"],
    ["classroom", "https://classroom.googleapis.com/v1/courses?pageSize=1"],
    ["drive", "https://www.googleapis.com/drive/v3/files?pageSize=1&fields=files(id%2CmimeType)"],
    ["driveactivity", "https://driveactivity.googleapis.com/v2/activity:query", { method: "POST", body: { pageSize: 1, ancestorName: "items/root" } }],
    ["drivelabels", "https://drivelabels.googleapis.com/v2/labels?publishedOnly=true&pageSize=1&view=LABEL_VIEW_BASIC"],
    ["contacts", "https://people.googleapis.com/v1/people/me/connections?personFields=names&pageSize=1"],
    ["tasks", "https://tasks.googleapis.com/tasks/v1/users/@me/lists?maxResults=1"],
    ["people", "https://people.googleapis.com/v1/people/me?personFields=names"],
    ["sites", "https://www.googleapis.com/drive/v3/files?pageSize=1&q=mimeType%3D%27application%2Fvnd.google-apps.site%27&fields=files(id%2CmimeType)"],
    ["analytics", "https://analyticsadmin.googleapis.com/v1beta/accountSummaries?pageSize=1"],
    ["searchconsole", "https://searchconsole.googleapis.com/webmasters/v3/sites"],
    ["youtube", "https://youtube.googleapis.com/youtube/v3/channels?part=id&mine=true&maxResults=1"],
    ["photos", "https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=1"],
  ];
  const direct = [];
  for (const [name, url, options] of directTests) direct.push(await directProbe(accessToken, name, url, options));

  const tests = [
    ["chat", ["chat", "spaces", "list", "--max", "1"]],
    ["classroom", ["classroom", "courses", "list", "--max", "1"]],
    ["drive", ["drive", "ls", "--all", "--max", "100", "--fields", "files(id,mimeType),nextPageToken"]],
    ["driveactivity", ["drive", "activity", "query", "--max", "1"]],
    ["drivelabels", ["drive", "labels", "list", "--max", "1"]],
    ["contacts", ["contacts", "list", "--max", "1"]],
    ["tasks", ["tasks", "lists", "list", "--max", "1"]],
    ["people", ["people", "me"]],
    ["sites", ["sites", "list", "--max", "1"]],
    ["analytics", ["analytics", "accounts", "--max", "1"]],
    ["searchconsole", ["searchconsole", "sites", "list"]],
    ["ads", ["ads", "customers", "list"]],
    ["youtube", ["youtube", "channels", "list", "--mine", "--max", "1"]],
    ["photos", ["photos", "list", "--max", "1"]],
  ];
  const raw = [];
  for (const [command, argv] of tests) raw.push(await runGog(accessToken, shapeManifest, command, argv));

  const drive = raw.find((result) => result.command === "drive");
  const items = Array.isArray(drive?.value) ? drive.value : Array.isArray(drive?.value?.files) ? drive.value.files : [];
  const resources = new Map([
    ["docs", "application/vnd.google-apps.document"],
    ["sheets", "application/vnd.google-apps.spreadsheet"],
    ["slides", "application/vnd.google-apps.presentation"],
    ["forms", "application/vnd.google-apps.form"],
    ["appscript", "application/vnd.google-apps.script"],
  ]);
  for (const [command, mimeType] of resources) {
    const resource = items.find((item) => item && typeof item === "object" && item.mimeType === mimeType && typeof item.id === "string");
    if (!resource) {
      raw.push(Object.freeze({ command, status: "not_testable_no_resource" }));
      continue;
    }
    const argv = command === "docs" ? ["docs", "info", resource.id]
      : command === "sheets" ? ["sheets", "metadata", resource.id]
      : command === "slides" ? ["slides", "info", resource.id]
      : command === "forms" ? ["forms", "get", resource.id]
      : ["appscript", "get", resource.id];
    const projection = command === "docs"
      ? "file.id,file.mimeType,document.documentId,document.revisionId,externalContent.untrusted,externalContent.source,externalContent.wrapped"
      : command === "sheets"
        ? "spreadsheetId,sheets.properties.sheetId,sheets.properties.gridProperties.rowCount,sheets.properties.gridProperties.columnCount,externalContent.untrusted,externalContent.source,externalContent.wrapped"
        : undefined;
    raw.push(await runGog(accessToken, shapeManifest, command, argv, projection));
  }
  raw.push(Object.freeze({ command: "meet", status: "not_testable_needs_meeting_reference" }));
  raw.push(Object.freeze({ command: "photospicker", status: "not_testable_needs_picker_session" }));

  const directFailures = direct.filter((result) => result.status !== "permission_ok").map((result) => result.command);
  const gogFailures = raw.filter((result) => result.status !== "contract_ok").map((result) => result.command);
  const gate = Object.freeze({ status: directFailures.length === 0 && gogFailures.length === 0 ? "passed" : "failed", directFailures: Object.freeze(directFailures), gogShapeOrExecutionFailures: Object.freeze(gogFailures) });
  process.stdout.write(`${JSON.stringify({ version: 1, connectorId, gogVersion: shapeManifest.gogVersion, grantScopeCount: selected.redeemed.metadata.scopes.length, gate, direct, gogcli: raw.map(publicResult) }, null, 2)}\n`);
  if (gate.status !== "passed") process.exitCode = 1;
}

main().catch(() => {
  process.stdout.write(`${JSON.stringify({ version: 1, status: "harness_failed" })}\n`);
  process.exitCode = 1;
});
