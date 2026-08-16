import type { HostActorContext } from "./identity.js";
import { trustedActorFromHostContext } from "./identity.js";
import type { WorkspaceId } from "./policy.js";
import { defineSubjectId, type SubjectId, type SubjectMappingStore } from "./subject.js";

const runBindingBrand: unique symbol = Symbol("TrustedRunBinding");

export interface TrustedWorkspaceSelection {
  /** Resolve only from authenticated host/session state, never tool arguments. */
  resolve(context: Readonly<HostActorContext>): Promise<WorkspaceId | null> | WorkspaceId | null;
  /** Recheck membership at binding and immediately before every execution. */
  isMember(subjectId: SubjectId, workspaceId: WorkspaceId): Promise<boolean> | boolean;
}

export interface TrustedRunBinding {
  readonly [runBindingBrand]: true;
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
}

export type RunBindingFailureCode =
  | "MISSING_TRUSTED_ACTOR"
  | "INVALID_TRUSTED_ACTOR"
  | "SUBJECT_NOT_MAPPED"
  | "WORKSPACE_NOT_SELECTED"
  | "INVALID_WORKSPACE_BINDING"
  | "WORKSPACE_ACCESS_DENIED";

export type TrustedRunBindingResult =
  | { readonly ok: true; readonly binding: TrustedRunBinding }
  | { readonly ok: false; readonly code: RunBindingFailureCode };

const metadata = new WeakMap<object, {
  readonly subjectId: SubjectId;
  readonly workspaceId: WorkspaceId;
  readonly workspaces: TrustedWorkspaceSelection;
}>();

export async function bindTrustedRun(options: {
  hostContext: Readonly<HostActorContext> | null | undefined;
  subjects: SubjectMappingStore;
  workspaces: TrustedWorkspaceSelection;
}): Promise<TrustedRunBindingResult> {
  const actor = trustedActorFromHostContext(options.hostContext);
  if (!actor.ok) return Object.freeze({ ok: false, code: actor.code });

  const subjectId = await options.subjects.resolve(actor.actorId);
  if (subjectId === null) return Object.freeze({ ok: false, code: "SUBJECT_NOT_MAPPED" });
  try { defineSubjectId(subjectId); } catch { return Object.freeze({ ok: false, code: "SUBJECT_NOT_MAPPED" }); }
  const workspaceId = await options.workspaces.resolve(Object.freeze({ ...options.hostContext }));
  if (workspaceId === null) return Object.freeze({ ok: false, code: "WORKSPACE_NOT_SELECTED" });
  if (!/^ws_[A-Za-z0-9_-]{6,96}$/.test(workspaceId)) return Object.freeze({ ok: false, code: "INVALID_WORKSPACE_BINDING" });
  if (!await options.workspaces.isMember(subjectId, workspaceId)) {
    return Object.freeze({ ok: false, code: "WORKSPACE_ACCESS_DENIED" });
  }

  const binding = Object.freeze({ [runBindingBrand]: true as const, subjectId, workspaceId });
  metadata.set(binding, Object.freeze({ subjectId, workspaceId, workspaces: options.workspaces }));
  return Object.freeze({ ok: true, binding });
}

/** Bind opaque deployment-owned provisioning input after the same membership check. */
export async function bindDeploymentRun(options: {
  subjectId: SubjectId;
  workspaceId: WorkspaceId;
  workspaces: Pick<TrustedWorkspaceSelection, "isMember">;
}): Promise<TrustedRunBindingResult> {
  try { defineSubjectId(options.subjectId); } catch { return Object.freeze({ ok: false, code: "SUBJECT_NOT_MAPPED" }); }
  if (!/^ws_[A-Za-z0-9_-]{6,96}$/.test(options.workspaceId)) return Object.freeze({ ok: false, code: "INVALID_WORKSPACE_BINDING" });
  if (!await options.workspaces.isMember(options.subjectId, options.workspaceId)) return Object.freeze({ ok: false, code: "WORKSPACE_ACCESS_DENIED" });
  const binding = Object.freeze({ [runBindingBrand]: true as const, subjectId: options.subjectId, workspaceId: options.workspaceId });
  metadata.set(binding, Object.freeze({ subjectId: options.subjectId, workspaceId: options.workspaceId, workspaces: { resolve: () => options.workspaceId, isMember: options.workspaces.isMember } }));
  return Object.freeze({ ok: true, binding });
}

export async function revalidateTrustedRun(binding: TrustedRunBinding): Promise<boolean> {
  const bound = metadata.get(binding);
  if (!bound || binding[runBindingBrand] !== true) return false;
  return await bound.workspaces.isMember(bound.subjectId, bound.workspaceId);
}

export function isTrustedRunBinding(value: unknown): value is TrustedRunBinding {
  return typeof value === "object" && value !== null &&
    (value as TrustedRunBinding)[runBindingBrand] === true && metadata.has(value);
}
