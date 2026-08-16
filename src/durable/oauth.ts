import { join } from "node:path";
import { unlink } from "node:fs/promises";
import type { OAuthStateBackend, OAuthStateRecord } from "../credentials/oauth.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, safeFileComponent, withFileLock } from "./files.js";

function statePath(root: string, stateId: string): string {
  return join(root, `${safeFileComponent(stateId, "OAuth state id")}.json`);
}

export class FileOAuthStateBackend implements OAuthStateBackend {
  constructor(readonly root: string) {}
  async create(record: OAuthStateRecord): Promise<void> {
    const root = await ensurePrivateDirectory(this.root);
    await withFileLock(root, safeFileComponent(record.stateId, "OAuth state id"), async () => {
      if (await readJsonFile(statePath(root, record.stateId)) !== null) throw new Error("OAUTH_STATE_COLLISION");
      await atomicWriteJson(statePath(root, record.stateId), record);
    });
  }
  async consume(stateId: string): Promise<OAuthStateRecord | null> {
    const root = await ensurePrivateDirectory(this.root);
    return await withFileLock(root, safeFileComponent(stateId, "OAuth state id"), async () => {
      const path = statePath(root, stateId);
      const value = await readJsonFile(path);
      if (value === null) return null;
      await unlink(path);
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("OAUTH_STATE_INVALID");
      return value as OAuthStateRecord;
    });
  }
}
