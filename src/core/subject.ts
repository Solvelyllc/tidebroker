import type { TrustedActorId } from "./identity.js";

declare const subjectIdBrand: unique symbol;

/** Random, deployment-issued identifier. It must not encode a provider subject. */
export type SubjectId = string & { readonly [subjectIdBrand]: true };

const SUBJECT_ID = /^usr_[A-Za-z0-9_-]{16,96}$/;

export function defineSubjectId(value: string): SubjectId {
  if (!SUBJECT_ID.test(value)) {
    throw new TypeError("Invalid deployment subject identifier.");
  }
  return value as SubjectId;
}

export interface SubjectMappingStore {
  /** Exact lookup only. Implementations must not guess from names or domains. */
  resolve(actorId: TrustedActorId): Promise<SubjectId | null> | SubjectId | null;
}

/**
 * Deployment-owned exact registry useful for durable-store adapters and tests.
 * The raw host tuple never leaves this mapping boundary.
 */
export class ExactSubjectRegistry implements SubjectMappingStore {
  readonly #subjects: ReadonlyMap<TrustedActorId, SubjectId>;

  constructor(entries: Iterable<readonly [TrustedActorId, SubjectId]>) {
    const subjects = new Map<TrustedActorId, SubjectId>();
    const opaqueIds = new Set<SubjectId>();
    for (const [actorId, subjectId] of entries) {
      defineSubjectId(subjectId);
      if (subjects.has(actorId) || opaqueIds.has(subjectId)) {
        throw new TypeError("Subject mappings must be one-to-one.");
      }
      subjects.set(actorId, subjectId);
      opaqueIds.add(subjectId);
    }
    this.#subjects = subjects;
  }

  resolve(actorId: TrustedActorId): SubjectId | null {
    return this.#subjects.get(actorId) ?? null;
  }
}
