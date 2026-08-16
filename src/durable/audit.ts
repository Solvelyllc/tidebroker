import { open, lstat } from "node:fs/promises";
import { join } from "node:path";
import type { AuditEvent, AuditSink } from "../audit/index.js";
import { ensurePrivateDirectory, safeFileComponent, withFileLock } from "./files.js";

export class FileAuditSink implements AuditSink {
  constructor(readonly root: string, readonly filename = "security-audit.jsonl") {
    safeFileComponent(filename, "audit filename");
  }
  async ready(): Promise<boolean> {
    try { await ensurePrivateDirectory(this.root); return true; } catch { return false; }
  }
  async append(event: Readonly<AuditEvent>): Promise<void> {
    const root = await ensurePrivateDirectory(this.root);
    await withFileLock(root, "audit", async () => {
      const path = join(root, this.filename);
      let handle;
      try {
        handle = await open(path, "a", 0o600);
        const info = await lstat(path);
        if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) throw new Error("AUDIT_FILE_INVALID");
        await handle.writeFile(`${JSON.stringify(event)}\n`, "utf8");
        await handle.sync();
      } finally { await handle?.close(); }
    });
  }
}
