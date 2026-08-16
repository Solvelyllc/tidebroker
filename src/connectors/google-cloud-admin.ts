import type { CredentialMaterial } from "../credentials/store.js";
import type { WorkerOperation } from "../worker/worker.js";
import { googleAccessToken } from "./google-oauth.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";

export const GOOGLE_PROJECT_SERVICES_ENABLE_ACTION = "project.services.enable" as const;
const SERVICE = /^[a-z][a-z0-9-]{0,62}(?:\.[a-z][a-z0-9-]{0,62})+$/;

export interface GoogleProjectServicesEnableInput { readonly services: readonly string[] }

export function validateGoogleProjectServicesEnableInput(value: unknown): Readonly<GoogleProjectServicesEnableInput> {
  if (typeof value !== "object" || value === null || Array.isArray(value) || Object.keys(value).length !== 1) throw new Error("GOOGLE_PROJECT_ADMIN_INPUT_INVALID");
  const services = (value as Record<string, unknown>).services;
  if (!Array.isArray(services) || services.length < 1 || services.length > 20 || services.some((item) => typeof item !== "string" || !SERVICE.test(item)) || new Set(services).size !== services.length) throw new Error("GOOGLE_PROJECT_ADMIN_INPUT_INVALID");
  return Object.freeze({ services: Object.freeze([...services].sort()) });
}

async function bounded(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > 256 * 1024) throw new Error("GOOGLE_PROJECT_ADMIN_RESPONSE_INVALID");
  try { const value = JSON.parse(text) as unknown; if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(); return value as Record<string, unknown>; }
  catch { throw new Error("GOOGLE_PROJECT_ADMIN_RESPONSE_INVALID"); }
}

function oauth(material: CredentialMaterial | undefined): Extract<CredentialMaterial, { kind: "oauth2" }> {
  if (!material || material.kind !== "oauth2") throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH");
  return material;
}

export function createGoogleProjectAdminOperations(projectId: string, options: { fetch?: typeof fetch } = {}): readonly WorkerOperation[] {
  if (!/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(projectId)) throw new Error("GOOGLE_PROJECT_ID_INVALID");
  const fetcher = options.fetch ?? fetch;
  return Object.freeze([{
    connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_PROJECT_SERVICES_ENABLE_ACTION, mutating: true,
    async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) {
      const input = validateGoogleProjectServicesEnableInput(raw); const accessToken = await googleAccessToken(oauth(material), fetcher);
      for (const service of input.services) {
        await assertCredentialActive();
        markProviderCallStarted();
        const url = `https://serviceusage.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/services/${encodeURIComponent(service)}:enable`;
        const response = await fetcher(url, { method: "POST", headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" }, body: "{}", redirect: "error", signal: AbortSignal.timeout(30_000) });
        if (!response.ok) throw new Error("GOOGLE_PROJECT_SERVICE_ENABLE_FAILED");
        const operation = await bounded(response); if (typeof operation.name !== "string" || operation.name.length > 1024) throw new Error("GOOGLE_PROJECT_ADMIN_RESPONSE_INVALID");
      }
      return Object.freeze({ enabled: input.services });
    },
  }]);
}
