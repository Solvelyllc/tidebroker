import { isAbsolute } from "node:path";
import { buildAuditEvent } from "../audit/index.js";
import { revokeGoogleCredential } from "../connectors/google-oauth.js";
import { defineCredentialHandle } from "../core/policy.js";
import { EncryptedCredentialStore } from "../credentials/store.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { FileAuditSink } from "../durable/audit.js";
import { FileCredentialRecordBackend } from "../durable/credentials.js";
import { readJsonFile } from "../durable/files.js";
import type { CredentialWorkerServiceConfig } from "./bootstrap.js";
import { SecureFileCredentialEncryptionKeys } from "./secure-key-files.js";

export interface CredentialRevocationRequest { readonly version: 1; readonly credentialHandle: string }

export async function loadCredentialRevocationRequest(path: string): Promise<CredentialRevocationRequest> {
  if (!isAbsolute(path)) throw new Error("REVOCATION_REQUEST_INVALID");
  const value = await readJsonFile(path, 16 * 1024);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("REVOCATION_REQUEST_INVALID");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["version", "credentialHandle"].includes(key)) || record.version !== 1 || typeof record.credentialHandle !== "string") throw new Error("REVOCATION_REQUEST_INVALID");
  defineCredentialHandle(record.credentialHandle);
  return record as unknown as CredentialRevocationRequest;
}

export async function runCredentialRevocation(worker: CredentialWorkerServiceConfig, request: CredentialRevocationRequest): Promise<{ providerRevoked: boolean }> {
  if (!worker.accountBindingsPath) throw new Error("REVOCATION_NOT_CONFIGURED");
  const handle = defineCredentialHandle(request.credentialHandle);
  const keys = new SecureFileCredentialEncryptionKeys(worker.encryption.activeKeyId, worker.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(worker.credentialRoot, worker.metadataRoot), keys);
  const metadata = await credentials.metadata(handle); if (!metadata) throw new Error("CREDENTIAL_NOT_FOUND");
  const redeemed = await credentials.redeem({ subjectId: metadata.subjectId, workspaceId: metadata.workspaceId, connectorId: metadata.connectorId, credentialHandle: handle, generation: metadata.generation });
  let providerRevoked = redeemed.material.kind !== "oauth2";
  if (redeemed.material.kind === "oauth2") { try { await revokeGoogleCredential(redeemed.material); providerRevoked = true; } catch {} }
  const revokedGeneration = await credentials.revoke(handle);
  await new FileAccountBindingStore(worker.accountBindingsPath).disable(handle, revokedGeneration);
  await new FileAuditSink(worker.auditRoot).append(buildAuditEvent({ actor: { id: metadata.subjectId, kind: metadata.principalKind }, workspace: metadata.workspaceId, connector: metadata.connectorId, action: "credential.revoke", outcome: "succeeded", correlation: { requestId: `req_${globalThis.crypto.randomUUID().replaceAll("-", "")}` }, reasonCode: providerRevoked ? "CREDENTIAL_REVOKED" : "CREDENTIAL_REVOKED_LOCAL" }));
  return Object.freeze({ providerRevoked });
}
