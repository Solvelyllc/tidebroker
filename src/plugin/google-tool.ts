import { Type } from "typebox";
import { ActorBroker } from "../broker.js";
import { ActorScopedGoogleCalendarRuntime, GOOGLE_CALENDAR_EVENTS_LIST_ACTION, GOOGLE_GOG_CONNECTOR_ID } from "../connectors/index.js";
import { trustedActorFromHostContext, type HostActorContext } from "../core/identity.js";
import { bindTrustedRun } from "../core/run-binding.js";
import { FileAuditSink, FileSubjectMappingStore, FileWorkspaceMembershipStore, durableWorkspaceSelection, parseDurableAccountBinding } from "../durable/index.js";
import { CredentialGrantIssuer } from "../worker/grant.js";
import { readSecureKeyFile } from "../worker/secure-key-files.js";
import { UnixCredentialWorkerClient } from "../worker/transport.js";
import { ACCOUNT_BINDING_DISCOVERY_HANDLE, ACCOUNT_BINDING_RESOLVE_ACTION } from "../worker/account-resolver.js";
import { deploymentReady, type ActorBrokerPluginConfig } from "./config.js";

export const googleCalendarListParameters = Type.Object({
  today: Type.Optional(Type.Boolean()),
  maxResults: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
}, { additionalProperties: false });

export function createGoogleCalendarTool(config: ActorBrokerPluginConfig, toolContext: HostActorContext & { readonly agentId?: string | null }) {
  const actor = trustedActorFromHostContext(toolContext);
  const workspaceId = config.agentWorkspaces.find((entry) => entry.agentId === toolContext.agentId)?.workspaceId;
  if (!actor.ok || !workspaceId || !deploymentReady(config)) return null;
  return {
    name: "google_calendar_events_list",
    label: "Google Calendar Events",
    description: "List events from the authenticated requester's policy-bound Google Calendar account.",
    parameters: googleCalendarListParameters,
    execute: async (toolCallId: string, params: unknown) => {
      try {
        const grantKey = await readSecureKeyFile(config.grant.keyFile);
        const memberships = new FileWorkspaceMembershipStore(config.workspaceMembershipsPath);
        const subjects = new FileSubjectMappingStore(config.subjectMappingsPath);
        const workspaces = durableWorkspaceSelection({ selectedWorkspace: () => workspaceId, memberships });
        const grants = new CredentialGrantIssuer({ secret: grantKey, issuer: config.grant.issuer, audience: config.grant.audience });
        const worker = new UnixCredentialWorkerClient({ socketPath: config.workerSocketPath });
        let configured = config.accounts.filter((account) => account.connectorId === GOOGLE_GOG_CONNECTOR_ID);
        if (config.workerAccountDiscovery) {
          const bound = await bindTrustedRun({ hostContext: toolContext, subjects, workspaces });
          if (!bound.ok) throw Object.assign(new Error(bound.code), { code: bound.code });
          const discovered = await worker.execute({ connectorId: GOOGLE_GOG_CONNECTOR_ID, action: ACCOUNT_BINDING_RESOLVE_ACTION,
            grant: grants.issue({ subjectId: bound.binding.subjectId, principalKind: "human", workspaceId: bound.binding.workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, action: ACCOUNT_BINDING_RESOLVE_ACTION, credentialHandle: ACCOUNT_BINDING_DISCOVERY_HANDLE, credentialGeneration: 1, requestId: `req_${globalThis.crypto.randomUUID().replaceAll("-", "")}` }), input: {} });
          configured = [parseDurableAccountBinding(discovered)];
        }
        const broker = new ActorBroker({ bindings: configured.map((account) => ({ ...account, principalKind: "human" as const })), operations: [{ connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION }], grants: new CredentialGrantIssuer({ secret: grantKey, issuer: config.grant.issuer, audience: config.grant.audience }), audit: new FileAuditSink(config.gatewayAuditRoot) });
        const runtime = new ActorScopedGoogleCalendarRuntime({ subjects, workspaces, broker, worker });
        const result = await runtime.listEvents(toolContext, toolCallId, params);
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }], details: result };
      } catch (error) {
        const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : "GOOGLE_CONNECTOR_DENIED";
        throw new Error(code);
      }
    },
  };
}
