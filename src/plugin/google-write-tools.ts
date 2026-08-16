import { Type, type TSchema } from "typebox";
import { ActorBroker } from "../broker.js";
import { canonicalPayloadDigest } from "../core/canonical.js";
import type { HostActorContext } from "../core/identity.js";
import { bindTrustedRun } from "../core/run-binding.js";
import { GOOGLE_CALENDAR_EVENT_CREATE_ACTION, GOOGLE_CALENDAR_EVENT_DELETE_ACTION, GOOGLE_CALENDAR_EVENT_UPDATE_ACTION, GOOGLE_GOG_CONNECTOR_ID, validateGoogleCalendarEventCreateInput, validateGoogleCalendarEventDeleteInput, validateGoogleCalendarEventUpdateInput } from "../connectors/index.js";
import { FileAuditSink, FileSubjectMappingStore, FileWorkspaceMembershipStore, durableWorkspaceSelection, parseDurableAccountBinding } from "../durable/index.js";
import { CredentialGrantIssuer } from "../worker/grant.js";
import { readSecureKeyFile } from "../worker/secure-key-files.js";
import { UnixCredentialWorkerClient } from "../worker/transport.js";
import { ACCOUNT_BINDING_DISCOVERY_HANDLE, ACCOUNT_BINDING_RESOLVE_ACTION } from "../worker/account-resolver.js";
import type { ActorBrokerPluginConfig } from "./config.js";
import { consumeGoogleWriteApproval } from "./write-approval.js";

const fields = {
  summary: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })), description: Type.Optional(Type.String({ minLength: 1, maxLength: 8192 })), location: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })),
  start: Type.Optional(Type.String({ minLength: 16, maxLength: 40 })), end: Type.Optional(Type.String({ minLength: 16, maxLength: 40 })), timeZone: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })), attendees: Type.Optional(Type.Array(Type.String({ minLength: 3, maxLength: 255 }), { maxItems: 100 })),
};
const createParameters = Type.Object({ ...fields, summary: Type.String({ minLength: 1, maxLength: 1024 }), start: Type.String({ minLength: 16, maxLength: 40 }), end: Type.String({ minLength: 16, maxLength: 40 }) }, { additionalProperties: false });
const updateParameters = Type.Object({ eventId: Type.String({ minLength: 5, maxLength: 1024 }), ...fields }, { additionalProperties: false });
const deleteParameters = Type.Object({ eventId: Type.String({ minLength: 5, maxLength: 1024 }) }, { additionalProperties: false });

export async function executeGoogleOperation(config: ActorBrokerPluginConfig, context: HostActorContext & { agentId?: string | null }, toolCallId: string, action: string, input: unknown): Promise<unknown> {
  const workspaceId = config.agentWorkspaces.find((entry) => entry.agentId === context.agentId)?.workspaceId; if (!workspaceId) throw new Error("RUN_NOT_BOUND");
  const key = await readSecureKeyFile(config.grant.keyFile); const memberships = new FileWorkspaceMembershipStore(config.workspaceMembershipsPath); const subjects = new FileSubjectMappingStore(config.subjectMappingsPath); const workspaces = durableWorkspaceSelection({ selectedWorkspace: () => workspaceId, memberships });
  const bound = await bindTrustedRun({ hostContext: context, subjects, workspaces }); if (!bound.ok) throw new Error(bound.code);
  const grants = new CredentialGrantIssuer({ secret: key, issuer: config.grant.issuer, audience: config.grant.audience }); const worker = new UnixCredentialWorkerClient({ socketPath: config.workerSocketPath });
  let configured = config.accounts;
  if (config.workerAccountDiscovery) {
    const discovered = await worker.execute({ connectorId: GOOGLE_GOG_CONNECTOR_ID, action: ACCOUNT_BINDING_RESOLVE_ACTION, grant: grants.issue({ subjectId: bound.binding.subjectId, principalKind: "human", workspaceId: bound.binding.workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, action: ACCOUNT_BINDING_RESOLVE_ACTION, credentialHandle: ACCOUNT_BINDING_DISCOVERY_HANDLE, credentialGeneration: 1, requestId: `req_${globalThis.crypto.randomUUID().replaceAll("-", "")}` }), input: {} }); configured = [parseDurableAccountBinding(discovered)];
  }
  const broker = new ActorBroker({ bindings: configured.map((account) => ({ ...account, principalKind: "human" as const, connectorId: GOOGLE_GOG_CONNECTOR_ID })), operations: [{ connectorId: GOOGLE_GOG_CONNECTOR_ID, action }], grants, audit: new FileAuditSink(config.gatewayAuditRoot) });
  const authorized = await broker.authorize({ binding: bound.binding, connectorId: GOOGLE_GOG_CONNECTOR_ID, action, requestId: toolCallId, inputDigest: canonicalPayloadDigest(input) });
  return await worker.execute({ ...authorized, input });
}

export function nonRetriableOutcomeUnknown(error: unknown): { content: readonly [{ type: "text"; text: string }]; details: Readonly<{ ok: false; outcome: "unknown"; retryable: false; code: "WORKER_OUTCOME_UNKNOWN" }> } | null {
  const code = typeof error === "object" && error !== null && "code" in error ? error.code : error instanceof Error ? error.message : undefined;
  if (code !== "WORKER_OUTCOME_UNKNOWN") return null;
  const details = Object.freeze({ ok: false as const, outcome: "unknown" as const, retryable: false as const, code: "WORKER_OUTCOME_UNKNOWN" as const });
  return { content: [{ type: "text" as const, text: JSON.stringify(details) }], details };
}

export function createGoogleCalendarWriteTools(config: ActorBrokerPluginConfig, context: HostActorContext & { agentId?: string | null }) {
  const make = (name: string, label: string, description: string, parameters: TSchema, action: string, validate: (value: unknown) => unknown) => ({ name, label, description, parameters, execute: async (toolCallId: string, raw: unknown) => { consumeGoogleWriteApproval(name, toolCallId, raw, context); const input = validate(raw); try { const result = await executeGoogleOperation(config, context, toolCallId, action, input); return { content: [{ type: "text" as const, text: JSON.stringify(result) }], details: result }; } catch (error) { const unknown = nonRetriableOutcomeUnknown(error); if (unknown) return unknown; const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : error instanceof Error && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.message) ? error.message : "GOOGLE_CONNECTOR_DENIED"; throw new Error(code); } } });
  return [
    make("google_calendar_event_create", "Create Google Calendar Event", "Create an event only after explicit one-time operator approval.", createParameters, GOOGLE_CALENDAR_EVENT_CREATE_ACTION, validateGoogleCalendarEventCreateInput),
    make("google_calendar_event_update", "Update Google Calendar Event", "Update an event only after explicit one-time operator approval.", updateParameters, GOOGLE_CALENDAR_EVENT_UPDATE_ACTION, validateGoogleCalendarEventUpdateInput),
    make("google_calendar_event_delete", "Delete Google Calendar Event", "Delete an event only after explicit one-time operator approval.", deleteParameters, GOOGLE_CALENDAR_EVENT_DELETE_ACTION, validateGoogleCalendarEventDeleteInput),
  ];
}
