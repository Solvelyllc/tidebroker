import { buildAuditEvent, type AuditSink } from "../audit/index.js";
import type { CredentialHandle } from "../core/policy.js";
import { EncryptedCredentialStore } from "./store.js";

export interface CredentialInvalidationTarget {
  invalidate(handle: CredentialHandle, revokedGeneration: number): Promise<void>;
}

export class CredentialRevocationManager {
  constructor(readonly options: { credentials: EncryptedCredentialStore; targets?: readonly CredentialInvalidationTarget[]; audit: AuditSink; newEventId?: () => string; now?: () => Date }) {}

  async revoke(handle: CredentialHandle, requestId: string): Promise<number> {
    const metadata = await this.options.credentials.metadata(handle);
    if (!metadata) throw new Error("CREDENTIAL_NOT_FOUND");
    const generation = await this.options.credentials.revoke(handle);
    await Promise.all((this.options.targets ?? []).map(async (target) => {
      try { await target.invalidate(handle, generation); } catch { /* Credential remains revoked. */ }
    }));
    const event = buildAuditEvent({ actor: { id: metadata.subjectId, kind: metadata.principalKind }, workspace: metadata.workspaceId, connector: metadata.connectorId, action: "credential.revoke", outcome: "succeeded", correlation: { requestId }, reasonCode: "CREDENTIAL_REVOKED" }, { newEventId: this.options.newEventId, now: this.options.now });
    await this.options.audit.append(event);
    return generation;
  }
}
