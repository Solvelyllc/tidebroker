import { execFileSync } from "node:child_process";
import { chmod, lstat, open, readFile, readdir } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

function fail() { throw new Error("OS_ISOLATION_EVIDENCE_FAILED"); }
function systemd(service, properties) {
  const output = execFileSync("systemctl", ["show", service, "--no-pager", ...properties.map((property) => `--property=${property}`)], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  return Object.fromEntries(output.trim().split("\n").filter(Boolean).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));
}
async function privateTree(root, uid) {
  const visit = async (path) => {
    const info = await lstat(path);
    if (info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o077) !== 0) fail();
    if (info.isDirectory()) for (const entry of await readdir(path)) await visit(join(path, entry));
    else if (!info.isFile()) fail();
  };
  await visit(root);
}
async function privateFile(path, uid) {
  if (typeof path !== "string" || !isAbsolute(path)) fail();
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o077) !== 0) fail();
}
function exactConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const record = value;
  if (record.version !== 1 || typeof record.credentialRoot !== "string") fail();
  return record;
}

export async function collectOsIsolationEvidence(options) {
  const { outputPath, workerConfigPath, gatewayUser, service = "tidebroker-worker.service", sourceCommit } = options ?? {};
  if (![outputPath, workerConfigPath].every((value) => typeof value === "string" && isAbsolute(value)) || typeof gatewayUser !== "string" || !gatewayUser || !/^[a-f0-9]{40,64}$/u.test(sourceCommit)) fail();
  const state = systemd(service, ["ActiveState", "SubState", "User", "NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome", "IPAddressDeny", "IPAddressAllow"]);
  if (state.ActiveState !== "active" || state.SubState !== "running" || !state.User || state.User === "root" || state.User === gatewayUser || state.NoNewPrivileges !== "yes" || state.PrivateTmp !== "yes" || state.ProtectSystem !== "strict" || state.ProtectHome !== "yes") fail();
  const configInfo = await lstat(workerConfigPath);
  if (!configInfo.isFile() || configInfo.isSymbolicLink() || configInfo.uid === 0 || (configInfo.mode & 0o077) !== 0) fail();
  const config = exactConfig(JSON.parse(await readFile(workerConfigPath, "utf8")));
  if (!isAbsolute(config.credentialRoot)) fail();
  await privateTree(config.credentialRoot, configInfo.uid);
  const secretPaths = [
    config.grant?.keyFile,
    ...(Array.isArray(config.encryption?.keys) ? config.encryption.keys.map((key) => key?.keyFile) : []),
    config.googleOAuth?.clientIdFile,
    config.googleOAuth?.clientSecretFile,
  ].filter((value) => value !== undefined);
  if (secretPaths.length < 3) fail();
  for (const path of secretPaths) await privateFile(path, configInfo.uid);
  const deny = state.IPAddressDeny?.split(/\s+/u).filter(Boolean) ?? [];
  const allow = state.IPAddressAllow?.split(/\s+/u).filter(Boolean) ?? [];
  if (!deny.includes("any") || allow.length === 0) fail();
  const verifiedAt = new Date().toISOString();
  const evidence = {
    version: 1,
    gate: "osIsolation",
    status: "passed",
    verifiedAt,
    sourceCommit,
    checks: ["worker-user-separated", "credential-files-isolated", "provider-egress-restricted"].map((id) => ({ id, status: "passed" })),
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
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    await collectOsIsolationEvidence({
      outputPath: process.env.TIDEBROKER_OS_EVIDENCE_PATH,
      workerConfigPath: process.env.TIDEBROKER_WORKER_CONFIG_PATH,
      gatewayUser: process.env.TIDEBROKER_GATEWAY_USER,
      service: process.env.TIDEBROKER_WORKER_SERVICE,
      sourceCommit,
    });
    process.stdout.write("OS_ISOLATION_EVIDENCE_WRITTEN\n");
  } catch {
    process.stderr.write("OS_ISOLATION_EVIDENCE_FAILED\n");
    process.exitCode = 1;
  }
}
