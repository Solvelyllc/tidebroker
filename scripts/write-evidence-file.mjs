import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, open, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

/** Publishes a complete owner-only evidence file without replacing an existing path. */
export async function writeEvidenceFile(outputPath, value) {
  const directory = dirname(outputPath);
  const temporary = join(directory, `.tidebroker-evidence-${randomUUID()}`);
  let handle; let temporaryExists = false;
  try {
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    temporaryExists = true;
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0 || typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("EVIDENCE_OUTPUT_INVALID");
    await handle.writeFile(value, "utf8");
    await handle.sync();
    await link(temporary, outputPath);
    await unlink(temporary);
    temporaryExists = false;
    const directoryHandle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally {
    try { await handle?.close(); }
    finally { if (temporaryExists) await unlink(temporary).catch(() => {}); }
  }
}
