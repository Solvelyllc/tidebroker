import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { CredentialEncryptionKeys } from "../credentials/store.js";

export async function readSecureKeyFile(path: string): Promise<Uint8Array> {
  if (!isAbsolute(path) || path.includes("\0")) throw new Error("SECURE_KEY_FILE_INVALID");
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== 32 || (opened.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())) throw new Error("SECURE_KEY_FILE_INVALID");
    const key = await handle.readFile();
    if (key.byteLength !== 32) throw new Error("SECURE_KEY_FILE_INVALID");
    return new Uint8Array(key);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("SECURE_KEY_FILE_INVALID");
    throw error;
  } finally { await handle?.close(); }
}

export async function readSecureTextFile(path: string, maxBytes = 4096): Promise<string> {
  if (!isAbsolute(path) || path.includes("\0") || !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("SECURE_TEXT_FILE_INVALID");
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size < 1 || opened.size > maxBytes || (opened.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())) throw new Error("SECURE_TEXT_FILE_INVALID");
    const value = (await handle.readFile({ encoding: "utf8" })).trim();
    if (!value || value.includes("\0") || /[\r\n]/u.test(value)) throw new Error("SECURE_TEXT_FILE_INVALID");
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("SECURE_TEXT_FILE_INVALID");
    throw error;
  } finally { await handle?.close(); }
}

export class SecureFileCredentialEncryptionKeys implements CredentialEncryptionKeys {
  readonly #keys: ReadonlyMap<string, string>;
  constructor(readonly activeKeyId: string, entries: readonly { readonly id: string; readonly path: string }[]) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(activeKeyId)) throw new TypeError("Invalid active encryption key id.");
    const keys = new Map<string, string>();
    for (const entry of entries) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.id) || keys.has(entry.id) || !isAbsolute(entry.path)) throw new TypeError("Invalid encryption key entry.");
      keys.set(entry.id, entry.path);
    }
    if (!keys.has(activeKeyId)) throw new TypeError("Active encryption key is not configured.");
    this.#keys = keys;
  }
  async active(): Promise<{ readonly id: string; readonly key: Uint8Array }> {
    return { id: this.activeKeyId, key: await readSecureKeyFile(this.#keys.get(this.activeKeyId)!) };
  }
  async byId(id: string): Promise<Uint8Array | null> {
    const path = this.#keys.get(id);
    return path ? await readSecureKeyFile(path) : null;
  }
}
