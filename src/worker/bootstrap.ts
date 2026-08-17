import { dirname, isAbsolute } from "node:path";
import { lstat } from "node:fs/promises";
import { ensurePrivateDirectory, readJsonFile } from "../durable/files.js";
import { FileAuditSink } from "../durable/audit.js";
import { FileCredentialRecordBackend } from "../durable/credentials.js";
import { FileGrantReplayStore } from "../durable/replay.js";
import { FileMutationOutcomeStore } from "../durable/outcomes.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { EncryptedCredentialStore } from "../credentials/store.js";
import { createGoogleGogCalendarListOperation } from "../connectors/google-gog.js";
import { validateGogExecutionOptions } from "../connectors/gog-executor.js";
import { loadGogAuthCatalog } from "../connectors/gog-auth-catalog.js";
import { createGoogleCalendarWriteOperations } from "../connectors/google-calendar-write.js";
import { createGoogleGmailOperations } from "../connectors/google-gmail.js";
import { createGoogleWorkspaceReadOperations } from "../connectors/google-workspace-read.js";
import { CredentialGrantVerifier } from "./grant.js";
import { IsolatedCredentialWorker } from "./worker.js";
import { probeUnixCredentialWorkerSocket, UnixCredentialWorkerServer } from "./transport.js";
import { readSecureKeyFile, readSecureTextFile, SecureFileCredentialEncryptionKeys } from "./secure-key-files.js";
import { createAccountBindingResolveOperation } from "./account-resolver.js";
import type { GoogleWorkspaceExecutionOptions } from "../connectors/google-api-executor.js";
import { createGoogleConnectionBeginOperation } from "./google-connection-operation.js";
import { GOOGLE_CONNECTOR_BINDING_ACTIONS, resolveGoogleConnectorCapabilitySelection } from "../connectors/google-capabilities.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import { GoogleConnectionSessionManager } from "./google-provisioning.js";

export interface CredentialWorkerServiceConfig {
  readonly version: 1;
  readonly socketPath: string;
  readonly socketAccess?: "owner" | "group";
  readonly socketGroupId?: number;
  readonly recoverStaleSocket: boolean;
  readonly credentialRoot: string;
  readonly metadataRoot: string;
  readonly replayRoot: string;
  readonly auditRoot: string;
  readonly outcomeRoot: string;
  readonly grant: { readonly issuer: string; readonly audience: string; readonly keyFile: string };
  readonly encryption: { readonly activeKeyId: string; readonly keys: readonly { readonly id: string; readonly keyFile: string }[] };
  readonly googleExecution:
    | { readonly backend: "direct"; readonly timeoutMs?: number; readonly maxResponseBytes?: number }
    | { readonly backend: "gog"; readonly executablePath: string; readonly executableSha256: string; readonly configRoot: string; readonly httpsProxy?: string; readonly timeoutMs?: number; readonly maxOutputBytes?: number };
  readonly oauthStateRoot?: string;
  readonly googleOAuth?: { readonly clientIdFile: string; readonly clientSecretFile?: string; readonly redirectUri: string };
  readonly accountBindingsPath?: string;
  readonly limits?: { readonly maxFrameBytes?: number; readonly timeoutMs?: number; readonly maxConcurrent?: number };
}

const TOP_KEYS = new Set(["version", "socketPath", "socketAccess", "socketGroupId", "recoverStaleSocket", "credentialRoot", "metadataRoot", "replayRoot", "auditRoot", "outcomeRoot", "grant", "encryption", "googleExecution", "oauthStateRoot", "googleOAuth", "accountBindingsPath", "limits"]);
const PATH_KEYS = ["socketPath", "credentialRoot", "metadataRoot", "replayRoot", "auditRoot", "outcomeRoot"] as const;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function exact(record: Record<string, unknown>, keys: readonly string[]): boolean { const allowed = new Set(keys); return Object.keys(record).every((key) => allowed.has(key)); }
function boundedInteger(value: unknown, minimum: number, maximum: number): boolean { return value === undefined || Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum; }

export function validateCredentialWorkerServiceConfig(value: unknown): CredentialWorkerServiceConfig {
  if (!plain(value) || !exact(value, [...TOP_KEYS]) || value.version !== 1 || value.recoverStaleSocket !== true && value.recoverStaleSocket !== false) throw new Error("WORKER_CONFIG_INVALID");
  if (value.socketAccess !== undefined && value.socketAccess !== "owner" && value.socketAccess !== "group" || value.socketAccess === "group" && (!Number.isSafeInteger(value.socketGroupId) || (value.socketGroupId as number) < 0) || value.socketAccess !== "group" && value.socketGroupId !== undefined) throw new Error("WORKER_CONFIG_INVALID");
  for (const key of PATH_KEYS) if (typeof value[key] !== "string" || !isAbsolute(value[key] as string) || (value[key] as string).includes("\0")) throw new Error("WORKER_CONFIG_INVALID");
  if (value.oauthStateRoot !== undefined && (typeof value.oauthStateRoot !== "string" || !isAbsolute(value.oauthStateRoot) || value.oauthStateRoot.includes("\0"))) throw new Error("WORKER_CONFIG_INVALID");
  if (value.accountBindingsPath !== undefined && (typeof value.accountBindingsPath !== "string" || !isAbsolute(value.accountBindingsPath) || value.accountBindingsPath.includes("\0"))) throw new Error("WORKER_CONFIG_INVALID");
  if (!plain(value.grant) || !exact(value.grant, ["issuer", "audience", "keyFile"]) || typeof value.grant.issuer !== "string" || !ID.test(value.grant.issuer) || typeof value.grant.audience !== "string" || !ID.test(value.grant.audience) || typeof value.grant.keyFile !== "string" || !isAbsolute(value.grant.keyFile)) throw new Error("WORKER_CONFIG_INVALID");
  if (!plain(value.encryption) || !exact(value.encryption, ["activeKeyId", "keys"]) || typeof value.encryption.activeKeyId !== "string" || !ID.test(value.encryption.activeKeyId) || !Array.isArray(value.encryption.keys) || value.encryption.keys.length < 1 || value.encryption.keys.length > 8) throw new Error("WORKER_CONFIG_INVALID");
  for (const entry of value.encryption.keys) if (!plain(entry) || !exact(entry, ["id", "keyFile"]) || typeof entry.id !== "string" || !ID.test(entry.id) || typeof entry.keyFile !== "string" || !isAbsolute(entry.keyFile)) throw new Error("WORKER_CONFIG_INVALID");
  if (!plain(value.googleExecution) || typeof value.googleExecution.backend !== "string") throw new Error("WORKER_CONFIG_INVALID");
  if (value.googleExecution.backend === "direct") {
    if (!exact(value.googleExecution, ["backend", "timeoutMs", "maxResponseBytes"]) || !boundedInteger(value.googleExecution.timeoutMs, 1_000, 120_000) || !boundedInteger(value.googleExecution.maxResponseBytes, 1_024, 4 * 1024 * 1024)) throw new Error("WORKER_CONFIG_INVALID");
  } else if (value.googleExecution.backend === "gog") {
    if (!exact(value.googleExecution, ["backend", "executablePath", "executableSha256", "configRoot", "httpsProxy", "timeoutMs", "maxOutputBytes"]) || typeof value.googleExecution.executablePath !== "string" || !isAbsolute(value.googleExecution.executablePath) || value.googleExecution.executablePath.includes("\0") || typeof value.googleExecution.executableSha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.googleExecution.executableSha256) || typeof value.googleExecution.configRoot !== "string" || !isAbsolute(value.googleExecution.configRoot) || value.googleExecution.configRoot.includes("\0") || value.googleExecution.httpsProxy !== undefined && typeof value.googleExecution.httpsProxy !== "string" || !boundedInteger(value.googleExecution.timeoutMs, 1_000, 120_000) || !boundedInteger(value.googleExecution.maxOutputBytes, 1_024, 4 * 1024 * 1024)) throw new Error("WORKER_CONFIG_INVALID");
    try { validateGogExecutionOptions(value.googleExecution as unknown as import("../connectors/gog-executor.js").GogExecutionOptions); } catch { throw new Error("WORKER_CONFIG_INVALID"); }
  } else throw new Error("WORKER_CONFIG_INVALID");
  if (value.googleOAuth !== undefined && (!plain(value.googleOAuth) || !exact(value.googleOAuth, ["clientIdFile", "clientSecretFile", "redirectUri"]) || typeof value.googleOAuth.clientIdFile !== "string" || !isAbsolute(value.googleOAuth.clientIdFile) || value.googleOAuth.clientSecretFile !== undefined && (typeof value.googleOAuth.clientSecretFile !== "string" || !isAbsolute(value.googleOAuth.clientSecretFile)) || typeof value.googleOAuth.redirectUri !== "string" || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/oauth\/google\/callback$/.test(value.googleOAuth.redirectUri))) throw new Error("WORKER_CONFIG_INVALID");
  if (value.googleOAuth !== undefined && (value.oauthStateRoot === undefined || value.accountBindingsPath === undefined) || value.googleOAuth === undefined && (value.oauthStateRoot !== undefined || value.accountBindingsPath !== undefined)) throw new Error("WORKER_CONFIG_INVALID");
  if (value.limits !== undefined && (!plain(value.limits) || !exact(value.limits, ["maxFrameBytes", "timeoutMs", "maxConcurrent"]) || !boundedInteger(value.limits.maxFrameBytes, 1_024, 4 * 1024 * 1024) || !boundedInteger(value.limits.timeoutMs, 1_000, 120_000) || !boundedInteger(value.limits.maxConcurrent, 1, 1_000))) throw new Error("WORKER_CONFIG_INVALID");
  return value as unknown as CredentialWorkerServiceConfig;
}

export async function loadCredentialWorkerServiceConfig(path: string): Promise<CredentialWorkerServiceConfig> {
  if (!isAbsolute(path)) throw new Error("WORKER_CONFIG_INVALID");
  const value = await readJsonFile(path, 64 * 1024);
  if (value === null) throw new Error("WORKER_CONFIG_INVALID");
  return validateCredentialWorkerServiceConfig(value);
}

export async function createCredentialWorkerService(config: CredentialWorkerServiceConfig): Promise<UnixCredentialWorkerServer> {
  const grantKey = await readSecureKeyFile(config.grant.keyFile);
  const encryptionKeys = new SecureFileCredentialEncryptionKeys(config.encryption.activeKeyId, config.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  await encryptionKeys.active();
  const keyFiles = await Promise.all([config.grant.keyFile, ...config.encryption.keys.map((entry) => entry.keyFile)].map((path) => lstat(path)));
  const keyInodes = new Set(keyFiles.map((info) => `${info.dev}:${info.ino}`));
  if (keyInodes.size !== keyFiles.length) throw new Error("WORKER_KEYS_MUST_BE_DISTINCT");
  if (config.googleOAuth) {
    await readSecureTextFile(config.googleOAuth.clientIdFile);
    if (config.googleOAuth.clientSecretFile) await readSecureTextFile(config.googleOAuth.clientSecretFile);
  }
  if (config.googleExecution.backend === "gog") {
    const executable = await lstat(config.googleExecution.executablePath);
    if (!executable.isFile() || executable.isSymbolicLink() || (executable.mode & 0o111) === 0) throw new Error("GOG_EXECUTABLE_INVALID");
  }
  const stateRoots = await Promise.all([config.credentialRoot, config.metadataRoot, config.replayRoot, config.auditRoot, config.outcomeRoot, ...(config.googleExecution.backend === "gog" ? [config.googleExecution.configRoot] : []), ...(config.oauthStateRoot ? [config.oauthStateRoot] : []), ...(config.accountBindingsPath ? [dirname(config.accountBindingsPath)] : [])].map(ensurePrivateDirectory));
  if (new Set(stateRoots).size !== stateRoots.length) throw new Error("WORKER_STATE_ROOTS_MUST_BE_DISTINCT");
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(config.credentialRoot, config.metadataRoot), encryptionKeys);
  const execution: GoogleWorkspaceExecutionOptions = config.googleExecution.backend === "direct"
    ? { backend: "direct", direct: { timeoutMs: config.googleExecution.timeoutMs, maxResponseBytes: config.googleExecution.maxResponseBytes } }
    : { backend: "gog", gog: { executablePath: config.googleExecution.executablePath, executableSha256: config.googleExecution.executableSha256, configRoot: config.googleExecution.configRoot, httpsProxy: config.googleExecution.httpsProxy, timeoutMs: config.googleExecution.timeoutMs, maxOutputBytes: config.googleExecution.maxOutputBytes } };
  const onboarding = config.googleOAuth && config.googleExecution.backend === "gog" ? await loadGogAuthCatalog({ executablePath: config.googleExecution.executablePath, executableSha256: config.googleExecution.executableSha256, configRoot: config.googleExecution.configRoot, timeoutMs: config.googleExecution.timeoutMs, maxOutputBytes: config.googleExecution.maxOutputBytes }) : undefined;
  const googleBindingStore = { legacyConnectorId: GOOGLE_GOG_CONNECTOR_ID, allowedActionsByConnector: new Map([[GOOGLE_GOG_CONNECTOR_ID, new Set(GOOGLE_CONNECTOR_BINDING_ACTIONS)]]) };
  if (config.accountBindingsPath) await new FileAccountBindingStore(config.accountBindingsPath, googleBindingStore).migrateLegacy();
  const operations = [createGoogleGogCalendarListOperation(execution), ...createGoogleCalendarWriteOperations(execution), ...createGoogleGmailOperations(execution), ...createGoogleWorkspaceReadOperations(execution), ...(config.accountBindingsPath ? [createAccountBindingResolveOperation(config.accountBindingsPath, GOOGLE_GOG_CONNECTOR_ID, googleBindingStore)] : [])];
  if (onboarding) {
    const manager = new GoogleConnectionSessionManager(config, onboarding);
    operations.push(createGoogleConnectionBeginOperation({ manager, resolveSelection: (services) => resolveGoogleConnectorCapabilitySelection(services, onboarding) }));
  }
  const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret: grantKey, issuer: config.grant.issuer, audience: config.grant.audience }), credentials, replay: new FileGrantReplayStore(config.replayRoot), audit: new FileAuditSink(config.auditRoot), outcomes: new FileMutationOutcomeStore(config.outcomeRoot) }, operations);
  return new UnixCredentialWorkerServer({ socketPath: config.socketPath, worker, recoverStaleSocket: config.recoverStaleSocket, socketAccess: config.socketAccess, socketGroupId: config.socketGroupId, ...config.limits });
}

export async function checkCredentialWorkerService(config: CredentialWorkerServiceConfig): Promise<boolean> {
  try {
    await readSecureKeyFile(config.grant.keyFile);
    await new SecureFileCredentialEncryptionKeys(config.encryption.activeKeyId, config.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile }))).active();
    return await probeUnixCredentialWorkerSocket(config.socketPath, config.socketAccess ?? "owner", config.socketGroupId);
  } catch { return false; }
}
