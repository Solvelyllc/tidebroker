import { defineCredentialHandle } from "../core/policy.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import type { GoogleOnboardingSelection } from "../connectors/google-capabilities.js";
import { GoogleConnectionSessionManager } from "./google-provisioning.js";
import { GOG_DEFAULT_USER_SERVICE_IDS, GOG_EXPLICIT_USER_SERVICE_IDS, GOG_USER_OAUTH_SERVICE_IDS, GOG_WORKSPACE_SERVICE_ACCOUNT_IDS, type GogUserOAuthServiceId } from "../connectors/google-capabilities.js";
export { GOG_DEFAULT_USER_SERVICE_IDS, GOG_EXPLICIT_USER_SERVICE_IDS, GOG_USER_OAUTH_SERVICE_IDS, GOG_WORKSPACE_SERVICE_ACCOUNT_IDS } from "../connectors/google-capabilities.js";
import type { WorkerOperation } from "./worker.js";
import type { CredentialGrantClaims } from "./grant.js";

export const GOOGLE_CONNECTION_BEGIN_ACTION = "google.connection.begin" as const;
export const GOOGLE_CONNECTION_PROVISIONING_HANDLE = defineCredentialHandle("cred_google_connection_provisioning");

export interface GoogleConnectionBeginInput { readonly services: readonly GogUserOAuthServiceId[] }

export function validateGoogleConnectionBeginInput(value: unknown): GoogleConnectionBeginInput {
  if (typeof value !== "object" || value === null || Array.isArray(value) || Object.keys(value).some((key) => key !== "services")) throw new Error("GOOGLE_CONNECTION_INPUT_INVALID");
  const services = (value as Record<string, unknown>).services;
  if (!Array.isArray(services) || services.length < 1 || services.length > GOG_USER_OAUTH_SERVICE_IDS.length || new Set(services).size !== services.length || services.some((service) => typeof service !== "string" || !GOG_USER_OAUTH_SERVICE_IDS.includes(service as GogUserOAuthServiceId))) throw new Error("GOOGLE_CONNECTION_INPUT_INVALID");
  return Object.freeze({ services: Object.freeze([...services] as GogUserOAuthServiceId[]) });
}

export function createGoogleConnectionBeginOperation(options: {
  readonly manager: GoogleConnectionSessionManager;
  readonly resolveSelection: (services: readonly GogUserOAuthServiceId[]) => GoogleOnboardingSelection;
}): WorkerOperation<GoogleConnectionBeginInput, Readonly<{ url: string; expiresAt: number; services: readonly string[] }>> {
  return Object.freeze({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    action: GOOGLE_CONNECTION_BEGIN_ACTION,
    mutating: false,
    requiresCredential: false,
    async execute({ claims }: { readonly claims: CredentialGrantClaims }, raw: GoogleConnectionBeginInput) {
      if (claims.credentialHandle !== GOOGLE_CONNECTION_PROVISIONING_HANDLE || claims.credentialGeneration !== 1 || claims.principalKind !== "human") throw new Error("GOOGLE_CONNECTION_DENIED");
      const input = validateGoogleConnectionBeginInput(raw);
      const selection = options.resolveSelection(input.services);
      const started = await options.manager.begin({ subjectId: claims.subjectId, workspaceId: claims.workspaceId }, selection);
      return Object.freeze({ ...started, services: Object.freeze([...input.services]) });
    },
  });
}
