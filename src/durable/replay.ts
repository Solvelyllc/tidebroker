import { join } from "node:path";
import type { GrantReplayStore } from "../worker/worker.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, withFileLock } from "./files.js";

interface ReplayFile { readonly version: 1; readonly nonces: Readonly<Record<string, number>> }

export class FileGrantReplayStore implements GrantReplayStore {
  constructor(readonly root: string, readonly now: () => number = () => Math.floor(Date.now() / 1000), readonly maxEntries = 100_000) {}
  async claim(nonce: string, expiresAt: number): Promise<boolean> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(nonce) || !Number.isSafeInteger(expiresAt)) return false;
    const root = await ensurePrivateDirectory(this.root);
    return await withFileLock(root, "replay", async () => {
      const path = join(root, "replay.json");
      const raw = await readJsonFile(path) as ReplayFile | null;
      const now = this.now();
      const nonces: Record<string, number> = Object.create(null) as Record<string, number>;
      if (raw !== null) {
        if (raw.version !== 1 || typeof raw.nonces !== "object" || raw.nonces === null) throw new Error("REPLAY_STATE_INVALID");
        for (const [key, expiry] of Object.entries(raw.nonces)) if (Number.isSafeInteger(expiry) && expiry > now) nonces[key] = expiry;
      }
      if (Object.hasOwn(nonces, nonce)) return false;
      if (Object.keys(nonces).length >= this.maxEntries) throw new Error("REPLAY_STATE_CAPACITY");
      nonces[nonce] = expiresAt;
      await atomicWriteJson(path, { version: 1, nonces });
      return true;
    });
  }
}
