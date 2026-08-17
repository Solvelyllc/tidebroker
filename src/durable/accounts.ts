import { dirname } from "node:path";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId, type AccountId, type ConnectorId, type CredentialHandle, type WorkspaceId } from "../core/policy.js";
import { defineSubjectId, type SubjectId } from "../core/subject.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, withFileLock } from "./files.js";
import { isConnectorActionId } from "../core/capabilities.js";

export interface DurableAccountBinding {
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
  readonly credentialGeneration: number;
  readonly allowedActions: readonly string[];
  readonly enabled: boolean;
}

interface AccountBindingFile { readonly version: 1 | 2; readonly entries: readonly DurableAccountBinding[] }

export interface AccountBindingStoreOptions {
  /** One-time reader for pre-v2 records; callers own the provider-specific migration choice. */
  readonly legacyConnectorId?: ConnectorId;
  readonly allowedActionsByConnector?: ReadonlyMap<ConnectorId, ReadonlySet<string>>;
}

export function parseDurableAccountBinding(value: unknown, options: AccountBindingStoreOptions = {}): DurableAccountBinding {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("ACCOUNT_BINDINGS_INVALID");
  const item = value as Record<string, unknown>;
  const allowed = new Set(["subjectId", "workspaceId", "connectorId", "accountId", "credentialHandle", "credentialGeneration", "allowedActions", "enabled"]);
  if (Object.keys(item).some((key) => !allowed.has(key)) || typeof item.subjectId !== "string" || typeof item.workspaceId !== "string" ||
    item.connectorId !== undefined && typeof item.connectorId !== "string" || item.connectorId === undefined && options.legacyConnectorId === undefined ||
    typeof item.accountId !== "string" || typeof item.credentialHandle !== "string" || !Number.isSafeInteger(item.credentialGeneration) ||
    (item.credentialGeneration as number) < 1 || !Array.isArray(item.allowedActions) || item.allowedActions.length > 256 ||
    new Set(item.allowedActions).size !== item.allowedActions.length || item.allowedActions.some((action) => !isConnectorActionId(action)) || item.enabled !== true && item.enabled !== false) throw new Error("ACCOUNT_BINDINGS_INVALID");
  const connectorId = item.connectorId === undefined ? options.legacyConnectorId! : defineConnectorId(item.connectorId as string);
  const connectorActions = options.allowedActionsByConnector?.get(connectorId);
  if ((options.allowedActionsByConnector && !connectorActions) || (connectorActions && item.allowedActions.some((action) => !connectorActions.has(action as string)))) throw new Error("ACCOUNT_BINDINGS_INVALID");
  return Object.freeze({
    subjectId: defineSubjectId(item.subjectId), workspaceId: defineWorkspaceId(item.workspaceId), accountId: defineAccountId(item.accountId),
    connectorId,
    credentialHandle: defineCredentialHandle(item.credentialHandle), credentialGeneration: item.credentialGeneration as number,
    allowedActions: Object.freeze([...(item.allowedActions as string[])]), enabled: item.enabled,
  });
}

export class FileAccountBindingStore {
  constructor(readonly path: string, readonly options: AccountBindingStoreOptions = {}) {}

  async list(): Promise<readonly DurableAccountBinding[]> {
    const value = await readJsonFile(this.path);
    if (value === null) return Object.freeze([]);
    if (typeof value !== "object" || Array.isArray(value) || ![1, 2].includes((value as Record<string, unknown>).version as number) ||
      !Array.isArray((value as Record<string, unknown>).entries)) throw new Error("ACCOUNT_BINDINGS_INVALID");
    const version = (value as unknown as AccountBindingFile).version;
    if (version === 1 && !this.options.legacyConnectorId) throw new Error("ACCOUNT_BINDINGS_MIGRATION_REQUIRED");
    const entries = ((value as unknown as AccountBindingFile).entries).map((entry) => parseDurableAccountBinding(entry, version === 1 ? this.options : { allowedActionsByConnector: this.options.allowedActionsByConnector }));
    const principals = new Set<string>(); const accounts = new Set<string>(); const handles = new Set<string>();
    for (const entry of entries) {
      const principal = `${entry.subjectId}\0${entry.workspaceId}\0${entry.connectorId}`;
      if (principals.has(principal) || accounts.has(entry.accountId) || handles.has(entry.credentialHandle)) throw new Error("ACCOUNT_BINDINGS_INVALID");
      principals.add(principal); accounts.add(entry.accountId); handles.add(entry.credentialHandle);
    }
    return Object.freeze(entries);
  }

  async upsert(binding: DurableAccountBinding): Promise<void> {
    await ensurePrivateDirectory(dirname(this.path));
    await withFileLock(dirname(this.path), "account-bindings", async () => {
      const entries = [...await this.list()].filter((entry) => entry.subjectId !== binding.subjectId || entry.workspaceId !== binding.workspaceId || entry.connectorId !== binding.connectorId);
      entries.push(parseDurableAccountBinding(binding, { allowedActionsByConnector: this.options.allowedActionsByConnector }));
      await atomicWriteJson(this.path, { version: 2, entries });
    });
  }

  /** Rewrites legacy provider-implicit records after the caller supplies the connector identity. */
  async migrateLegacy(): Promise<boolean> {
    if (!this.options.legacyConnectorId) return false;
    await ensurePrivateDirectory(dirname(this.path));
    return await withFileLock(dirname(this.path), "account-bindings", async () => {
      const value = await readJsonFile(this.path);
      if (value === null || typeof value !== "object" || Array.isArray(value) || (value as Record<string, unknown>).version === 2) return false;
      if ((value as Record<string, unknown>).version !== 1 || !Array.isArray((value as Record<string, unknown>).entries)) throw new Error("ACCOUNT_BINDINGS_INVALID");
      const entries = ((value as unknown as AccountBindingFile).entries).map((entry) => parseDurableAccountBinding(entry, this.options));
      await atomicWriteJson(this.path, { version: 2, entries });
      return true;
    });
  }

  async disable(handle: CredentialHandle, revokedGeneration: number): Promise<void> {
    await ensurePrivateDirectory(dirname(this.path));
    await withFileLock(dirname(this.path), "account-bindings", async () => {
      const entries = [...await this.list()];
      const index = entries.findIndex((entry) => entry.credentialHandle === handle);
      if (index < 0) return;
      entries[index] = Object.freeze({ ...entries[index]!, credentialGeneration: revokedGeneration, enabled: false });
      await atomicWriteJson(this.path, { version: 2, entries });
    });
  }
}
