import { join } from "node:path";
import type { CredentialHandle } from "../core/policy.js";
import type { CredentialMetadataReader } from "../broker.js";
import type { CredentialRecordBackend, CredentialRecordMetadata, EncryptedCredentialRecord } from "../credentials/store.js";
import { atomicWriteJson, ensurePrivateDirectory, readJsonFile, safeFileComponent, withFileLock } from "./files.js";

function recordPath(root: string, handle: CredentialHandle): string {
  return join(root, `${safeFileComponent(handle, "credential handle")}.json`);
}

function isRecord(value: unknown): value is EncryptedCredentialRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.keyId === "string" && typeof record.iv === "string" &&
    typeof record.ciphertext === "string" && typeof record.tag === "string" &&
    typeof record.metadata === "object" && record.metadata !== null;
}

/** Worker-private encrypted records plus a separate, non-secret metadata projection. */
export class FileCredentialRecordBackend implements CredentialRecordBackend {
  constructor(readonly privateRoot: string, readonly metadataRoot: string) {}

  async get(handle: CredentialHandle): Promise<EncryptedCredentialRecord | null> {
    const root = await ensurePrivateDirectory(this.privateRoot);
    const value = await readJsonFile(recordPath(root, handle));
    if (value === null) return null;
    if (!isRecord(value)) throw new Error("CREDENTIAL_RECORD_INVALID");
    return value;
  }

  async put(record: EncryptedCredentialRecord): Promise<void> {
    const handle = record.metadata.credentialHandle;
    const privateRoot = await ensurePrivateDirectory(this.privateRoot);
    const metadataRoot = await ensurePrivateDirectory(this.metadataRoot);
    if (privateRoot === metadataRoot) throw new Error("CREDENTIAL_ROOTS_MUST_BE_SEPARATE");
    await withFileLock(privateRoot, safeFileComponent(handle, "credential handle"), async () => {
      await atomicWriteJson(recordPath(privateRoot, handle), record);
      await atomicWriteJson(recordPath(metadataRoot, handle), record.metadata);
    });
  }
}

export class FileCredentialMetadataReader implements CredentialMetadataReader {
  constructor(readonly metadataRoot: string) {}
  async metadata(handle: CredentialHandle): Promise<CredentialRecordMetadata | null> {
    const root = await ensurePrivateDirectory(this.metadataRoot);
    const value = await readJsonFile(recordPath(root, handle));
    if (value === null) return null;
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("CREDENTIAL_METADATA_INVALID");
    return value as CredentialRecordMetadata;
  }
}
