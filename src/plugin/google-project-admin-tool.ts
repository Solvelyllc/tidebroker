import { Type } from "typebox";
import { GOOGLE_PROJECT_SERVICES_ENABLE_ACTION, validateGoogleProjectServicesEnableInput } from "../connectors/google-cloud-admin.js";
import type { HostActorContext } from "../core/identity.js";
import type { ActorBrokerPluginConfig } from "./config.js";
import { executeGoogleOperation } from "./google-write-tools.js";
import { consumeGoogleWriteApproval } from "./write-approval.js";

export const GOOGLE_PROJECT_SERVICES_ENABLE_TOOL = "google_project_services_enable" as const;
const parameters = Type.Object({ services: Type.Array(Type.String({ minLength: 3, maxLength: 255, pattern: "^[a-z][a-z0-9-]{0,62}(?:\\.[a-z][a-z0-9-]{0,62})+$" }), { minItems: 1, maxItems: 20, uniqueItems: true }) }, { additionalProperties: false });

export function createGoogleProjectAdminTool(config: ActorBrokerPluginConfig, context: HostActorContext & { agentId?: string | null }) {
  return { name: GOOGLE_PROJECT_SERVICES_ENABLE_TOOL, label: "Enable Google APIs", description: "Enable explicitly approved APIs in the deployment's existing Google Cloud project.", parameters,
    execute: async (toolCallId: string, raw: unknown) => {
      consumeGoogleWriteApproval(GOOGLE_PROJECT_SERVICES_ENABLE_TOOL, toolCallId, raw, context); const input = validateGoogleProjectServicesEnableInput(raw);
      try { const result = await executeGoogleOperation(config, context, toolCallId, GOOGLE_PROJECT_SERVICES_ENABLE_ACTION, input); return { content: [{ type: "text" as const, text: JSON.stringify(result) }], details: result }; }
      catch (error) { const code = error instanceof Error && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.message) ? error.message : "GOOGLE_PROJECT_ADMIN_DENIED"; throw new Error(code); }
    } };
}
