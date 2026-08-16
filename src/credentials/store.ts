import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { AccountId, ConnectorId, CredentialHandle, WorkspaceId } from "../core/policy.js";
import type { SubjectId } from "../core/subject.js";

export type CredentialMaterial =
  | { readonly kind: "oauth2"; readonly refreshToken: string; readonly clientId: string; readonly clientSecret?: string }
  | { readonly kind: "gog-profile"; readonly configDirectory: string; readonly accountAlias: string };

export interface CredentialRecordMetadata {
  readonly subjectId: SubjectId;
  readonly principalKind: "human" | "service";
  readonly workspaceId: WorkspaceId;
  readonly connectorId: ConnectorId;
  readonly accountId: AccountId;
  readonly credentialHandle: CredentialHandle;
  readonly generation: number;
  readonly scopes: readonly string[];
  readonly state: "active" | "revoked";
}

export interface EncryptedCredentialRecord {
  readonly metadata: CredentialRecordMetadata;
  readonly keyId: string;
  readonly iv: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export interface CredentialRecordBackend {
  get(handle: CredentialHandle): Promise<EncryptedCredentialRecord | null>;
  put(record: EncryptedCredentialRecord): Promise<void>;
}

export class MemoryCredentialRecordBackend implements CredentialRecordBackend {
  readonly #records = new Map<CredentialHandle, EncryptedCredentialRecord>();
  async get(handle: CredentialHandle): Promise<EncryptedCredentialRecord | null> { return this.#records.get(handle) ?? null; }
  async put(record: EncryptedCredentialRecord): Promise<void> { this.#records.set(record.metadata.credentialHandle, record); }
}

export interface CredentialEncryptionKeys {
  active(): Promise<{ readonly id: string; readonly key: Uint8Array }> | { readonly id: string; readonly key: Uint8Array };
  byId(id: string): Promise<Uint8Array | null> | Uint8Array | null;
}

export class StaticCredentialEncryptionKeys implements CredentialEncryptionKeys {
  readonly #id: string;
  readonly #key: Uint8Array;
  constructor(id: string, key: Uint8Array) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id) || key.byteLength !== 32) throw new TypeError("Invalid credential encryption key.");
    this.#id = id;
    this.#key = new Uint8Array(key);
  }
  active() { return { id: this.#id, key: new Uint8Array(this.#key) }; }
  byId(id: string) { return id === this.#id ? new Uint8Array(this.#key) : null; }
}

export type CredentialStoreFailureCode =
  | "CREDENTIAL_NOT_FOUND" | "CREDENTIAL_REVOKED" | "CREDENTIAL_BINDING_MISMATCH"
  | "CREDENTIAL_GENERATION_MISMATCH" | "CREDENTIAL_DECRYPTION_FAILED";

export class CredentialStoreError extends Error {
  constructor(readonly code: CredentialStoreFailureCode) { super(code); this.name = "CredentialStoreError"; }
}

function aad(metadata: CredentialRecordMetadata): Buffer {
  return Buffer.from(JSON.stringify({
    subjectId: metadata.subjectId, principalKind: metadata.principalKind, workspaceId: metadata.workspaceId, connectorId: metadata.connectorId,
    accountId: metadata.accountId, credentialHandle: metadata.credentialHandle, generation: metadata.generation,
    scopes: metadata.scopes, state: metadata.state,
  }), "utf8");
}

function validateMaterial(value: CredentialMaterial): void {
  if (value.kind === "oauth2") {
    if (!value.refreshToken || !value.clientId || value.refreshToken.includes("\0") || value.clientId.includes("\0") || value.clientSecret?.includes("\0")) throw new TypeError("Invalid OAuth credential material.");
  } else if (!value.configDirectory || !value.accountAlias || value.configDirectory.includes("\0") || value.accountAlias.includes("\0")) {
    throw new TypeError("Invalid gog profile material.");
  }
}

export class EncryptedCredentialStore {
  constructor(readonly backend: CredentialRecordBackend, readonly keys: CredentialEncryptionKeys) {}

  async store(metadata: Omit<CredentialRecordMetadata, "state">, material: CredentialMaterial): Promise<void> {
    validateMaterial(material);
    if (metadata.principalKind !== "human" && metadata.principalKind !== "service") throw new TypeError("Invalid credential principal kind.");
    if (!Number.isSafeInteger(metadata.generation) || metadata.generation < 1) throw new TypeError("Credential generation must be positive.");
    const frozenMetadata = Object.freeze({ ...metadata, scopes: Object.freeze([...metadata.scopes]), state: "active" as const });
    await this.#write(frozenMetadata, material);
  }

  async metadata(handle: CredentialHandle): Promise<CredentialRecordMetadata | null> {
    const record = await this.backend.get(handle);
    return record ? Object.freeze({ ...record.metadata, scopes: Object.freeze([...record.metadata.scopes]) }) : null;
  }

  async redeem(expected: {
    subjectId: SubjectId; workspaceId: WorkspaceId; connectorId: ConnectorId;
    credentialHandle: CredentialHandle; generation: number;
  }): Promise<{ readonly metadata: CredentialRecordMetadata; readonly material: CredentialMaterial }> {
    const record = await this.backend.get(expected.credentialHandle);
    if (!record) throw new CredentialStoreError("CREDENTIAL_NOT_FOUND");
    const meta = record.metadata;
    if (meta.subjectId !== expected.subjectId || meta.workspaceId !== expected.workspaceId || meta.connectorId !== expected.connectorId) throw new CredentialStoreError("CREDENTIAL_BINDING_MISMATCH");
    if (meta.state !== "active") throw new CredentialStoreError("CREDENTIAL_REVOKED");
    if (meta.generation !== expected.generation) throw new CredentialStoreError("CREDENTIAL_GENERATION_MISMATCH");
    const key = await this.keys.byId(record.keyId);
    if (!key || key.byteLength !== 32) throw new CredentialStoreError("CREDENTIAL_DECRYPTION_FAILED");
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.iv, "base64url"));
      decipher.setAAD(aad(meta));
      decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "base64url")), decipher.final()]);
      const material = JSON.parse(plaintext.toString("utf8")) as CredentialMaterial;
      validateMaterial(material);
      return Object.freeze({ metadata: Object.freeze({ ...meta, scopes: Object.freeze([...meta.scopes]) }), material: Object.freeze({ ...material }) });
    } catch (error) {
      if (error instanceof CredentialStoreError) throw error;
      throw new CredentialStoreError("CREDENTIAL_DECRYPTION_FAILED");
    }
  }

  async revoke(handle: CredentialHandle): Promise<number> {
    const record = await this.backend.get(handle);
    if (!record) throw new CredentialStoreError("CREDENTIAL_NOT_FOUND");
    const material = await this.#decryptUnchecked(record);
    const generation = record.metadata.generation + 1;
    await this.#write(Object.freeze({ ...record.metadata, generation, state: "revoked" as const }), material);
    return generation;
  }

  async #decryptUnchecked(record: EncryptedCredentialRecord): Promise<CredentialMaterial> {
    const key = await this.keys.byId(record.keyId);
    if (!key) throw new CredentialStoreError("CREDENTIAL_DECRYPTION_FAILED");
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.iv, "base64url"));
      decipher.setAAD(aad(record.metadata));
      decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "base64url")), decipher.final()]).toString("utf8")) as CredentialMaterial;
    } catch { throw new CredentialStoreError("CREDENTIAL_DECRYPTION_FAILED"); }
  }

  async #write(metadata: CredentialRecordMetadata, material: CredentialMaterial): Promise<void> {
    const active = await this.keys.active();
    if (active.key.byteLength !== 32) throw new TypeError("Credential encryption key must be 32 bytes.");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", active.key, iv);
    cipher.setAAD(aad(metadata));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(material), "utf8"), cipher.final()]);
    await this.backend.put(Object.freeze({ metadata, keyId: active.id, iv: iv.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") }));
  }
}
