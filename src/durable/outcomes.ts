import { join } from "node:path";
import type { MutationIntent, MutationOutcomeStore, MutationOutcomeStatus } from "../worker/worker.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, withFileLock } from "./files.js";

interface OutcomeFile { readonly version: 1; readonly operations: Readonly<Record<string, MutationIntent & { readonly status: MutationOutcomeStatus }>> }

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_ACTION = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,15}$/;
const SAFE_DIGEST = /^[A-Za-z0-9_-]{43}$/;

function validIntent(value: MutationIntent): boolean {
  return SAFE_ID.test(value.requestId) && SAFE_ID.test(value.connectorId) && SAFE_ACTION.test(value.action) && SAFE_DIGEST.test(value.inputDigest);
}

export class FileMutationOutcomeStore implements MutationOutcomeStore {
  constructor(readonly root: string, readonly maxEntries = 100_000) {}

  async begin(intent: MutationIntent): Promise<boolean> {
    if (!validIntent(intent)) return false;
    return await this.#update(intent.requestId, (operations) => {
      if (Object.hasOwn(operations, intent.requestId)) return false;
      if (Object.keys(operations).length >= this.maxEntries) throw new Error("MUTATION_OUTCOME_CAPACITY");
      operations[intent.requestId] = Object.freeze({ ...intent, status: "pending" });
      return true;
    });
  }

  async complete(requestId: string, status: Exclude<MutationOutcomeStatus, "pending">): Promise<void> {
    if (!SAFE_ID.test(requestId)) throw new Error("MUTATION_OUTCOME_INVALID");
    await this.#update(requestId, (operations) => {
      const current = operations[requestId];
      if (!current || current.status !== "pending") throw new Error("MUTATION_OUTCOME_INVALID");
      operations[requestId] = Object.freeze({ ...current, status });
    });
  }

  async get(requestId: string): Promise<Readonly<(MutationIntent & { readonly status: MutationOutcomeStatus })> | null> {
    if (!SAFE_ID.test(requestId)) return null;
    const root = await ensurePrivateDirectory(this.root);
    const raw = await readJsonFile(join(root, "outcomes.json")) as OutcomeFile | null;
    return raw?.operations[requestId] ?? null;
  }

  async #update<T>(requestId: string, update: (operations: Record<string, MutationIntent & { status: MutationOutcomeStatus }>) => T): Promise<T> {
    const root = await ensurePrivateDirectory(this.root);
    return await withFileLock(root, "outcomes", async () => {
      const path = join(root, "outcomes.json");
      const raw = await readJsonFile(path) as OutcomeFile | null;
      if (raw !== null && (raw.version !== 1 || typeof raw.operations !== "object" || raw.operations === null || Array.isArray(raw.operations))) throw new Error("MUTATION_OUTCOME_INVALID");
      const operations = Object.assign(Object.create(null) as Record<string, MutationIntent & { status: MutationOutcomeStatus }>, raw?.operations ?? {});
      const result = update(operations);
      await atomicWriteJson(path, { version: 1, operations });
      return result;
    });
  }
}
