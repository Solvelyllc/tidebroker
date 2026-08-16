import { defineCredentialHandle } from "../core/policy.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import type { WorkerOperation } from "./worker.js";
import type { CredentialGrantClaims } from "./grant.js";

export const ACCOUNT_BINDING_RESOLVE_ACTION = "account.binding.resolve" as const;
export const ACCOUNT_BINDING_DISCOVERY_HANDLE = defineCredentialHandle("cred_account_binding_discovery");

export function createAccountBindingResolveOperation(path: string): WorkerOperation<Record<string, never>, unknown> {
  return Object.freeze({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    action: ACCOUNT_BINDING_RESOLVE_ACTION,
    mutating: false,
    requiresCredential: false,
    async execute({ claims }: { readonly claims: CredentialGrantClaims }, input: Record<string, never>) {
      if (typeof input !== "object" || input === null || Array.isArray(input) || Object.keys(input).length !== 0 || claims.credentialHandle !== ACCOUNT_BINDING_DISCOVERY_HANDLE || claims.credentialGeneration !== 1) throw new Error("ACCOUNT_BINDING_RESOLVE_DENIED");
      const matches = (await new FileAccountBindingStore(path).list()).filter((entry) => entry.enabled && entry.subjectId === claims.subjectId && entry.workspaceId === claims.workspaceId);
      if (matches.length !== 1) throw new Error("ACCOUNT_BINDING_RESOLVE_DENIED");
      return matches[0];
    },
  });
}
