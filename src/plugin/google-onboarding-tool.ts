import { Type } from "typebox";
import type { HostActorContext } from "../core/identity.js";
import { bindTrustedRun } from "../core/run-binding.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import { FileSubjectMappingStore, FileWorkspaceMembershipStore, durableWorkspaceSelection } from "../durable/index.js";
import { GOOGLE_CONNECTION_BEGIN_ACTION, GOOGLE_CONNECTION_PROVISIONING_HANDLE } from "../worker/google-connection-operation.js";
import { GOG_USER_OAUTH_SERVICE_IDS } from "../connectors/google-capabilities.js";
import { CredentialGrantIssuer } from "../worker/grant.js";
import { readSecureKeyFile } from "../worker/secure-key-files.js";
import { UnixCredentialWorkerClient } from "../worker/transport.js";
import type { ActorBrokerPluginConfig } from "./config.js";

const service = Type.Union(GOG_USER_OAUTH_SERVICE_IDS.map((id) => Type.Literal(id)));
export const googleWorkspaceConnectParameters = Type.Object({ services: Type.Array(service, { minItems: 1, maxItems: GOG_USER_OAUTH_SERVICE_IDS.length, uniqueItems: true }) }, { additionalProperties: false });

export function createGoogleWorkspaceConnectTool(config: ActorBrokerPluginConfig, context: HostActorContext & { readonly agentId?: string | null }) {
  const workspaceId = config.agentWorkspaces.find((entry) => entry.agentId === context.agentId)?.workspaceId;
  if (!workspaceId) return null;
  return {
    name: "google_workspace_connect",
    label: "Connect Google Workspace",
    description: "Start an actor-bound Google OAuth connection after presenting an inline structured multi-select. Supports gogcli's 22 default user services plus explicit Photos Picker. Admin, Groups, and Keep require a separate service-account/domain-wide-delegation setup. Never request or paste an OAuth code or callback URL in chat.",
    parameters: googleWorkspaceConnectParameters,
    execute: async (toolCallId: string, input: { readonly services: readonly string[] }) => {
      try {
        const memberships = new FileWorkspaceMembershipStore(config.workspaceMembershipsPath); const subjects = new FileSubjectMappingStore(config.subjectMappingsPath);
        const bound = await bindTrustedRun({ hostContext: context, subjects, workspaces: durableWorkspaceSelection({ selectedWorkspace: () => workspaceId, memberships }) });
        if (!bound.ok) throw new Error(bound.code);
        const grants = new CredentialGrantIssuer({ secret: await readSecureKeyFile(config.grant.keyFile), issuer: config.grant.issuer, audience: config.grant.audience });
        const result = await new UnixCredentialWorkerClient({ socketPath: config.workerSocketPath }).execute({ connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CONNECTION_BEGIN_ACTION, grant: grants.issue({ subjectId: bound.binding.subjectId, principalKind: "human", workspaceId: bound.binding.workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CONNECTION_BEGIN_ACTION, credentialHandle: GOOGLE_CONNECTION_PROVISIONING_HANDLE, credentialGeneration: 1, requestId: toolCallId }), input });
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }], details: result };
      } catch (error) { const code = error instanceof Error && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.message) ? error.message : "GOOGLE_CONNECTION_DENIED"; throw new Error(code); }
    },
  };
}
