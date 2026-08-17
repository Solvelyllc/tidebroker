import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";
import { writeEvidenceFile } from "./write-evidence-file.mjs";

function fail() { throw new Error("OS_ISOLATION_EVIDENCE_FAILED"); }
function systemd(service, properties) {
  const output = execFileSync("systemctl", ["show", service, "--no-pager", ...properties.map((property) => `--property=${property}`)], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  return Object.fromEntries(output.trim().split("\n").filter(Boolean).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));
}
async function privateTree(root, uid) {
  const visit = async (path) => {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const info = await handle.stat();
      if (info.uid !== uid || (info.mode & 0o077) !== 0) fail();
      if (info.isDirectory()) {
        const descriptorPath = `/proc/self/fd/${handle.fd}`;
        for (const entry of await readdir(descriptorPath)) await visit(join(descriptorPath, entry));
      } else if (!info.isFile()) fail();
    } catch { fail(); }
    finally { await handle?.close(); }
  };
  await visit(root);
}
async function privateFile(path, uid) {
  if (typeof path !== "string" || !isAbsolute(path)) fail();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.uid !== uid || (info.mode & 0o077) !== 0) fail();
  } catch { fail(); }
  finally { await handle?.close(); }
}
function exactConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const record = value;
  if (record.version !== 1 || typeof record.credentialRoot !== "string") fail();
  return record;
}

export function providerEgressRestricted(deny, allow) {
  if (!Array.isArray(deny) || !Array.isArray(allow)) return false;
  const deniesAll = deny.includes("any") || deny.includes("0.0.0.0/0") && deny.includes("::/0");
  const allowed = new Set(allow);
  return deniesAll && allowed.size === 2 && allowed.has("127.0.0.0/8") && allowed.has("::1/128");
}

export async function collectOsIsolationEvidence(options) {
  const { outputPath, workerConfigPath, gatewayUser, service = "tidebroker-worker.service", sourceCommit } = options ?? {};
  if (![outputPath, workerConfigPath].every((value) => typeof value === "string" && isAbsolute(value)) || typeof gatewayUser !== "string" || !gatewayUser || !/^[a-f0-9]{40,64}$/u.test(sourceCommit)) fail();
  const state = systemd(service, ["ActiveState", "SubState", "User", "NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome", "IPAddressDeny", "IPAddressAllow"]);
  if (state.ActiveState !== "active" || state.SubState !== "running" || !state.User || state.User === "root" || state.User === gatewayUser || state.NoNewPrivileges !== "yes" || state.PrivateTmp !== "yes" || state.ProtectSystem !== "strict" || state.ProtectHome !== "yes") fail();
  let configHandle; let configInfo; let config;
  try {
    configHandle = await open(workerConfigPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    configInfo = await configHandle.stat();
    if (!configInfo.isFile() || configInfo.size > 64 * 1024 || configInfo.uid === 0 || (configInfo.mode & 0o077) !== 0) fail();
    config = exactConfig(JSON.parse(await configHandle.readFile({ encoding: "utf8" })));
  } catch { fail(); }
  finally { await configHandle?.close(); }
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
  if (!providerEgressRestricted(deny, allow)) fail();
  const verifiedAt = new Date().toISOString();
  const evidence = {
    version: 1,
    gate: "osIsolation",
    status: "passed",
    verifiedAt,
    sourceCommit,
    checks: ["worker-user-separated", "credential-files-isolated", "provider-egress-restricted"].map((id) => ({ id, status: "passed" })),
  };
  await writeEvidenceFile(outputPath, `${JSON.stringify(evidence)}\n`).catch(fail);
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
