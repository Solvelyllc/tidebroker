import { open, mkdir, lstat, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { randomUUID } from "node:crypto";

const FILE_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,195}$/;

export function safeFileComponent(value: string, label: string): string {
  if (!FILE_COMPONENT.test(value)) throw new TypeError(`${label} is not a safe opaque identifier.`);
  return value;
}

export async function ensurePrivateDirectory(path: string): Promise<string> {
  if (!isAbsolute(path) || path.includes("\0")) throw new TypeError("Durable state directory must be absolute.");
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) throw new Error("DURABLE_DIRECTORY_NOT_PRIVATE");
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("DURABLE_DIRECTORY_WRONG_OWNER");
  return await realpath(path);
}

export async function readJsonFile(path: string, maxBytes = 4 * 1024 * 1024): Promise<unknown | null> {
  let handle;
  try {
    const pathInfo = await lstat(path);
    if (pathInfo.isSymbolicLink()) throw new Error("DURABLE_FILE_INVALID");
    handle = await open(path, "r");
    const info = await handle.stat();
    if (!info.isFile() || info.size > maxBytes || (info.mode & 0o077) !== 0) throw new Error("DURABLE_FILE_INVALID");
    const content = await handle.readFile({ encoding: "utf8" });
    return JSON.parse(content) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

export async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  const directory = await ensurePrivateDirectory(dirname(path));
  const target = join(directory, safeFileComponent(path.slice(path.lastIndexOf("/") + 1), "state filename"));
  const temporary = join(directory, `.tmp-${randomUUID()}`);
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(JSON.stringify(value), { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, target);
    const directoryHandle = await open(directory, "r");
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } catch (error) {
    await handle?.close();
    try { await unlink(temporary); } catch {}
    throw error;
  }
}

export async function withFileLock<T>(root: string, name: string, operation: () => Promise<T>): Promise<T> {
  const directory = await ensurePrivateDirectory(root);
  const lockPath = join(directory, `${safeFileComponent(name, "lock name")}.lock`);
  const deadline = Date.now() + 5_000;
  while (true) {
    try { await mkdir(lockPath, { mode: 0o700 }); break; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" || Date.now() >= deadline) throw new Error("DURABLE_LOCK_UNAVAILABLE");
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }
  try { return await operation(); }
  finally { try { await rmdir(lockPath); } catch {} }
}
