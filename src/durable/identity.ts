import type { HostActorContext, TrustedActorId } from "../core/identity.js";
import { defineWorkspaceId, type WorkspaceId } from "../core/policy.js";
import type { TrustedWorkspaceSelection } from "../core/run-binding.js";
import { defineSubjectId, type SubjectId, type SubjectMappingStore } from "../core/subject.js";
import { atomicWriteJson, readJsonFile } from "./files.js";

interface SubjectFile { readonly version: 1; readonly entries: readonly { readonly actorId: string; readonly subjectId: string }[] }
interface MembershipFile { readonly version: 1; readonly entries: readonly { readonly subjectId: string; readonly workspaceId: string }[] }

export async function writeSubjectMappings(path: string, entries: Iterable<readonly [TrustedActorId, SubjectId]>): Promise<void> {
  const output: { actorId: string; subjectId: string }[] = [];
  const actors = new Set<string>(); const subjects = new Set<string>();
  for (const [actorId, subjectId] of entries) {
    defineSubjectId(subjectId);
    if (actors.has(actorId) || subjects.has(subjectId)) throw new TypeError("Subject mappings must be one-to-one.");
    actors.add(actorId); subjects.add(subjectId); output.push({ actorId, subjectId });
  }
  await atomicWriteJson(path, { version: 1, entries: output });
}

export class FileSubjectMappingStore implements SubjectMappingStore {
  constructor(readonly path: string) {}
  async resolve(actorId: TrustedActorId): Promise<SubjectId | null> {
    const value = await readJsonFile(this.path) as SubjectFile | null;
    if (!value || value.version !== 1 || !Array.isArray(value.entries)) return null;
    const matches = value.entries.filter((entry) => entry.actorId === actorId);
    if (matches.length !== 1) return null;
    try { return defineSubjectId(matches[0]!.subjectId); } catch { return null; }
  }
}

export async function writeWorkspaceMemberships(path: string, entries: Iterable<readonly [SubjectId, WorkspaceId]>): Promise<void> {
  const output: { subjectId: string; workspaceId: string }[] = [];
  const exact = new Set<string>();
  for (const [subjectId, workspaceId] of entries) {
    defineSubjectId(subjectId);
    if (!/^ws_[A-Za-z0-9_-]{6,96}$/.test(workspaceId)) throw new TypeError("Workspace id must be opaque.");
    const key = `${subjectId}\0${workspaceId}`;
    if (exact.has(key)) throw new TypeError("Duplicate workspace membership.");
    exact.add(key); output.push({ subjectId, workspaceId });
  }
  await atomicWriteJson(path, { version: 1, entries: output });
}

export class FileWorkspaceMembershipStore {
  constructor(readonly path: string) {}
  async isMember(subjectId: SubjectId, workspaceId: WorkspaceId): Promise<boolean> {
    const value = await readJsonFile(this.path) as MembershipFile | null;
    if (!value || value.version !== 1 || !Array.isArray(value.entries)) return false;
    return value.entries.some((entry) => entry.subjectId === subjectId && entry.workspaceId === workspaceId);
  }
}

export function durableWorkspaceSelection(options: {
  selectedWorkspace(context: Readonly<HostActorContext>): Promise<string | null> | string | null;
  memberships: FileWorkspaceMembershipStore;
}): TrustedWorkspaceSelection {
  return {
    async resolve(context) {
      const selected = await options.selectedWorkspace(context);
      if (selected === null) return null;
      try { return defineWorkspaceId(selected); } catch { return null; }
    },
    isMember: (subjectId, workspaceId) => options.memberships.isMember(subjectId, workspaceId),
  };
}
