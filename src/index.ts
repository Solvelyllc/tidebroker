import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { trustedActorFromHostContext } from "./core/identity.js";
import { resolveActorBrokerPluginConfig } from "./plugin/config.js";
import { createGoogleCalendarTool } from "./plugin/google-tool.js";
import { createGoogleCalendarWriteTools } from "./plugin/google-write-tools.js";
import { requireGoogleWriteApproval } from "./plugin/write-approval.js";
import { createGoogleGmailTools } from "./plugin/google-gmail-tools.js";
import { createGoogleWorkspaceConnectTool } from "./plugin/google-onboarding-tool.js";
import { createGoogleWorkspaceReadTools } from "./plugin/google-workspace-read-tools.js";

const statusParameters = Type.Object({}, { additionalProperties: false });

export default definePluginEntry({
  id: "tidebroker",
  name: "Tidebroker",
  description:
    "Binds connector execution to OpenClaw's trusted requester identity without exposing credentials to the model.",
  register(api) {
    const deployment = resolveActorBrokerPluginConfig(api.pluginConfig ?? {});
    api.registerTool(
      (toolContext) => {
        const actor = trustedActorFromHostContext(toolContext);
        if (!actor.ok) {
          // Cron, heartbeat, public, and unbound subagent runs receive no
          // actor-scoped tool surface. There is deliberately no fallback.
          return null;
        }
        return {
          name: "tidebroker_status",
          label: "Tidebroker Status",
          description:
            "Check whether this turn has a trusted actor context for actor-scoped connectors.",
          parameters: statusParameters,
          execute: async () => {
            const details = {
              authenticated: true,
              principalKind: "human" as const,
              identitySource: "openclaw-host-context" as const,
              ...(toolContext.agentId ? { agentId: toolContext.agentId } : {}),
              ...(toolContext.messageChannel
                ? { messageChannel: toolContext.messageChannel }
                : {}),
            };
            return {
              content: [{ type: "text" as const, text: JSON.stringify(details) }],
              details,
            };
          },
        };
      },
      { name: "tidebroker_status", optional: true },
    );
    if (deployment) {
      api.registerTool((toolContext) => {
        if (!trustedActorFromHostContext(toolContext).ok) return null;
        return createGoogleWorkspaceConnectTool(deployment, toolContext);
      }, { name: "google_workspace_connect", optional: true });
      api.on("before_tool_call", (event, context) => requireGoogleWriteApproval(event, context) as never, { priority: 100 });
      api.registerTool(
        (toolContext) => createGoogleCalendarTool(deployment, toolContext),
        { name: "google_calendar_events_list", optional: true },
      );
      for (const name of ["google_calendar_event_create", "google_calendar_event_update", "google_calendar_event_delete"] as const) {
        api.registerTool((toolContext) => {
          if (!trustedActorFromHostContext(toolContext).ok) return null;
          return createGoogleCalendarWriteTools(deployment, toolContext).find((tool) => tool.name === name) ?? null;
        }, { name, optional: true });
      }
      for (const name of ["google_gmail_messages_search", "google_gmail_message_get", "google_gmail_message_send"] as const) {
        api.registerTool((toolContext) => {
          if (!trustedActorFromHostContext(toolContext).ok) return null;
          return createGoogleGmailTools(deployment, toolContext).find((tool) => tool.name === name) ?? null;
        }, { name, optional: true });
      }
      for (const name of ["google_drive_files_list", "google_docs_document_metadata", "google_sheets_spreadsheet_metadata"] as const) {
        api.registerTool((toolContext) => {
          if (!trustedActorFromHostContext(toolContext).ok) return null;
          return createGoogleWorkspaceReadTools(deployment, toolContext).find((tool) => tool.name === name) ?? null;
        }, { name, optional: true });
      }
    }
  },
});
