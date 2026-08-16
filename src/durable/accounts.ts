import { dirname } from "node:path";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId, type AccountId, type CredentialHandle, type WorkspaceId } from "../core/policy.js";
import { defineSubjectId, type SubjectId } from "../core/subject.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, withFileLock } from "./files.js";
import { GOOGLE_CALENDAR_EVENTS_LIST_ACTION } from "../connectors/google-gog.js";
import { GOOGLE_CALENDAR_WRITE_ACTIONS } from "../connectors/google-calendar-write.js";
import { GOOGLE_PROJECT_SERVICES_ENABLE_ACTION } from "../connectors/google-cloud-admin.js";
import { GOOGLE_GMAIL_ACTIONS } from "../connectors/google-gmail.js";

export const GOOGLE_CALENDAR_ALLOWED_ACTIONS = [GOOGLE_CALENDAR_EVENTS_LIST_ACTION, ...GOOGLE_CALENDAR_WRITE_ACTIONS, GOOGLE_PROJECT_SERVICES_ENABLE_ACTION, ...GOOGLE_GMAIL_ACTIONS] as const;
export type GoogleCalendarAllowedAction = (typeof GOOGLE_CALENDAR_ALLOWED_ACTIONS)[number];

export interface DurableAccountBinding {
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
  readonly credentialGeneration: number;
  readonly allowedActions: readonly GoogleCalendarAllowedAction[];
  readonly enabled: boolean;
}

interface AccountBindingFile { readonly version: 1; readonly entries: readonly DurableAccountBinding[] }

export function parseDurableAccountBinding(value: unknown): DurableAccountBinding {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("ACCOUNT_BINDINGS_INVALID");
  const item = value as Record<string, unknown>;
  const allowed = new Set(["subjectId", "workspaceId", "accountId", "credentialHandle", "credentialGeneration", "allowedActions", "enabled"]);
  if (Object.keys(item).some((key) => !allowed.has(key)) || typeof item.subjectId !== "string" || typeof item.workspaceId !== "string" ||
    typeof item.accountId !== "string" || typeof item.credentialHandle !== "string" || !Number.isSafeInteger(item.credentialGeneration) ||
    (item.credentialGeneration as number) < 1 || !Array.isArray(item.allowedActions) || item.allowedActions.length < 1 || item.allowedActions.length > GOOGLE_CALENDAR_ALLOWED_ACTIONS.length ||
    new Set(item.allowedActions).size !== item.allowedActions.length || item.allowedActions.some((action) => !GOOGLE_CALENDAR_ALLOWED_ACTIONS.includes(action as GoogleCalendarAllowedAction)) || item.enabled !== true && item.enabled !== false) throw new Error("ACCOUNT_BINDINGS_INVALID");
  return Object.freeze({
    subjectId: defineSubjectId(item.subjectId), workspaceId: defineWorkspaceId(item.workspaceId), accountId: defineAccountId(item.accountId),
    credentialHandle: defineCredentialHandle(item.credentialHandle), credentialGeneration: item.credentialGeneration as number,
    allowedActions: Object.freeze([...(item.allowedActions as GoogleCalendarAllowedAction[])]), enabled: item.enabled,
  });
}

export class FileAccountBindingStore {
  constructor(readonly path: string) {}

  async list(): Promise<readonly DurableAccountBinding[]> {
    const value = await readJsonFile(this.path);
    if (value === null) return Object.freeze([]);
    if (typeof value !== "object" || Array.isArray(value) || (value as Record<string, unknown>).version !== 1 ||
      !Array.isArray((value as Record<string, unknown>).entries)) throw new Error("ACCOUNT_BINDINGS_INVALID");
    const entries = ((value as unknown as AccountBindingFile).entries).map(parseDurableAccountBinding);
    const principals = new Set<string>(); const accounts = new Set<string>(); const handles = new Set<string>();
    for (const entry of entries) {
      const principal = `${entry.subjectId}\0${entry.workspaceId}`;
      if (principals.has(principal) || accounts.has(entry.accountId) || handles.has(entry.credentialHandle)) throw new Error("ACCOUNT_BINDINGS_INVALID");
      principals.add(principal); accounts.add(entry.accountId); handles.add(entry.credentialHandle);
    }
    return Object.freeze(entries);
  }

  async upsert(binding: DurableAccountBinding): Promise<void> {
    await ensurePrivateDirectory(dirname(this.path));
    await withFileLock(dirname(this.path), "account-bindings", async () => {
      const entries = [...await this.list()].filter((entry) => entry.subjectId !== binding.subjectId || entry.workspaceId !== binding.workspaceId);
      entries.push(parseDurableAccountBinding(binding));
      await atomicWriteJson(this.path, { version: 1, entries });
    });
  }

  async disable(handle: CredentialHandle, revokedGeneration: number): Promise<void> {
    await ensurePrivateDirectory(dirname(this.path));
    await withFileLock(dirname(this.path), "account-bindings", async () => {
      const entries = [...await this.list()];
      const index = entries.findIndex((entry) => entry.credentialHandle === handle);
      if (index < 0) return;
      entries[index] = Object.freeze({ ...entries[index]!, credentialGeneration: revokedGeneration, enabled: false });
      await atomicWriteJson(this.path, { version: 1, entries });
    });
  }
}
