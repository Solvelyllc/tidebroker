import { isAbsolute } from "node:path";
import { lstatSync } from "node:fs";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId, type AccountId, type CredentialHandle, type WorkspaceId } from "../core/policy.js";
import { defineSubjectId, type SubjectId } from "../core/subject.js";
import { GOOGLE_CALENDAR_EVENTS_LIST_ACTION } from "../connectors/google-gog.js";
import { GOOGLE_CALENDAR_ALLOWED_ACTIONS, type GoogleCalendarAllowedAction } from "../durable/accounts.js";

export interface PluginAccountBindingConfig {
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
  readonly credentialGeneration: number;
  readonly allowedActions: readonly GoogleCalendarAllowedAction[];
  readonly enabled: boolean;
}

export interface ActorBrokerPluginConfig {
  readonly enabled: boolean;
  readonly workerSocketPath: string;
  readonly workerSocketAccess?: "owner" | "group";
  readonly workerSocketGroupId?: number;
  readonly subjectMappingsPath: string;
  readonly workspaceMembershipsPath: string;
  readonly gatewayAuditRoot: string;
  readonly workerAccountDiscovery?: boolean;
  readonly grant: { readonly issuer: string; readonly audience: string; readonly keyFile: string };
  readonly agentWorkspaces: readonly { readonly agentId: string; readonly workspaceId: WorkspaceId }[];
  readonly accounts: readonly PluginAccountBindingConfig[];
}

const TOP = ["enabled", "workerSocketPath", "workerSocketAccess", "workerSocketGroupId", "subjectMappingsPath", "workspaceMembershipsPath", "gatewayAuditRoot", "workerAccountDiscovery", "grant", "agentWorkspaces", "accounts"];
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(record: Record<string, unknown>, allowed: readonly string[]): boolean { const keys = new Set(allowed); return Object.keys(record).every((key) => keys.has(key)); }

export function resolveActorBrokerPluginConfig(value: unknown): ActorBrokerPluginConfig | null {
  if (!plain(value)) return null;
  if (!exact(value, TOP)) throw new Error("PLUGIN_CONFIG_INVALID");
  if (value.enabled !== true) return null;
  if (value.workerSocketAccess !== undefined && value.workerSocketAccess !== "owner" && value.workerSocketAccess !== "group" || value.workerSocketAccess === "group" && (!Number.isSafeInteger(value.workerSocketGroupId) || (value.workerSocketGroupId as number) < 0) || value.workerSocketAccess !== "group" && value.workerSocketGroupId !== undefined) throw new Error("PLUGIN_CONFIG_INVALID");
  for (const field of ["workerSocketPath", "subjectMappingsPath", "workspaceMembershipsPath", "gatewayAuditRoot"] as const) if (typeof value[field] !== "string" || !isAbsolute(value[field] as string) || (value[field] as string).includes("\0")) throw new Error("PLUGIN_CONFIG_INVALID");
  if (value.workerAccountDiscovery !== undefined && typeof value.workerAccountDiscovery !== "boolean") throw new Error("PLUGIN_CONFIG_INVALID");
  if (!plain(value.grant) || !exact(value.grant, ["issuer", "audience", "keyFile"]) || typeof value.grant.issuer !== "string" || !ID.test(value.grant.issuer) || typeof value.grant.audience !== "string" || !ID.test(value.grant.audience) || typeof value.grant.keyFile !== "string" || !isAbsolute(value.grant.keyFile)) throw new Error("PLUGIN_CONFIG_INVALID");
  if (!Array.isArray(value.agentWorkspaces) || value.agentWorkspaces.length < 1 || value.accounts !== undefined && !Array.isArray(value.accounts) || value.accounts === undefined && value.workerAccountDiscovery !== true) throw new Error("PLUGIN_CONFIG_INVALID");
  const agentWorkspaces: { agentId: string; workspaceId: WorkspaceId }[] = []; const agentIds = new Set<string>();
  for (const item of value.agentWorkspaces) {
    if (!plain(item) || !exact(item, ["agentId", "workspaceId"]) || typeof item.agentId !== "string" || !ID.test(item.agentId) || typeof item.workspaceId !== "string" || agentIds.has(item.agentId)) throw new Error("PLUGIN_CONFIG_INVALID");
    const workspaceId = defineWorkspaceId(item.workspaceId); if (!/^ws_[A-Za-z0-9_-]{6,96}$/.test(workspaceId)) throw new Error("PLUGIN_CONFIG_INVALID");
    agentIds.add(item.agentId); agentWorkspaces.push({ agentId: item.agentId, workspaceId });
  }
  const accounts: PluginAccountBindingConfig[] = []; const bindings = new Set<string>();
  for (const item of (value.accounts ?? []) as unknown[]) {
    if (!plain(item) || !exact(item, ["subjectId", "workspaceId", "accountId", "credentialHandle", "credentialGeneration", "allowedActions", "enabled"]) || typeof item.subjectId !== "string" || typeof item.workspaceId !== "string" || typeof item.accountId !== "string" || typeof item.credentialHandle !== "string" || !Number.isSafeInteger(item.credentialGeneration) || (item.credentialGeneration as number) < 1 || item.enabled !== true && item.enabled !== false || !Array.isArray(item.allowedActions) || item.allowedActions.length < 1 || item.allowedActions.length > GOOGLE_CALENDAR_ALLOWED_ACTIONS.length || new Set(item.allowedActions).size !== item.allowedActions.length || item.allowedActions.some((action) => !GOOGLE_CALENDAR_ALLOWED_ACTIONS.includes(action as GoogleCalendarAllowedAction))) throw new Error("PLUGIN_CONFIG_INVALID");
    const subjectId = defineSubjectId(item.subjectId); const workspaceId = defineWorkspaceId(item.workspaceId); const accountId = defineAccountId(item.accountId); const credentialHandle = defineCredentialHandle(item.credentialHandle);
    const bindingKey = `${subjectId}\0${workspaceId}`; if (bindings.has(bindingKey)) throw new Error("PLUGIN_CONFIG_INVALID"); bindings.add(bindingKey);
    accounts.push({ subjectId, workspaceId, accountId, credentialHandle, credentialGeneration: item.credentialGeneration as number, allowedActions: Object.freeze([...(item.allowedActions as GoogleCalendarAllowedAction[])]), enabled: item.enabled });
  }
  return Object.freeze({ enabled: true, workerSocketPath: value.workerSocketPath as string, ...(value.workerSocketAccess === undefined ? {} : { workerSocketAccess: value.workerSocketAccess }), ...(value.workerSocketGroupId === undefined ? {} : { workerSocketGroupId: value.workerSocketGroupId as number }), subjectMappingsPath: value.subjectMappingsPath as string, workspaceMembershipsPath: value.workspaceMembershipsPath as string, gatewayAuditRoot: value.gatewayAuditRoot as string, ...(value.workerAccountDiscovery === undefined ? {} : { workerAccountDiscovery: value.workerAccountDiscovery as boolean }), grant: Object.freeze(value.grant as unknown as ActorBrokerPluginConfig["grant"]), agentWorkspaces: Object.freeze(agentWorkspaces.map((entry) => Object.freeze(entry))), accounts: Object.freeze(accounts.map((entry) => Object.freeze(entry))) });
}

function securePath(path: string, kind: "file" | "directory" | "socket", size?: number): boolean {
  try {
    const info = lstatSync(path);
    if ((info.mode & 0o077) !== 0 || (typeof process.getuid === "function" && info.uid !== process.getuid())) return false;
    if (kind === "file" && (!info.isFile() || info.isSymbolicLink() || size !== undefined && info.size !== size)) return false;
    if (kind === "directory" && (!info.isDirectory() || info.isSymbolicLink())) return false;
    if (kind === "socket" && !info.isSocket()) return false;
    return true;
  } catch { return false; }
}

export function deploymentReady(config: ActorBrokerPluginConfig): boolean {
  let socketReady = false;
  try { const socket = lstatSync(config.workerSocketPath); const mode = socket.mode & 0o777; socketReady = socket.isSocket() && (config.workerSocketAccess === "group" ? mode === 0o660 && socket.gid === config.workerSocketGroupId : mode === 0o600 && (typeof process.getuid !== "function" || socket.uid === process.getuid())); } catch {}
  return socketReady && securePath(config.subjectMappingsPath, "file") &&
    securePath(config.workspaceMembershipsPath, "file") && securePath(config.gatewayAuditRoot, "directory") &&
    securePath(config.grant.keyFile, "file", 32);
}
