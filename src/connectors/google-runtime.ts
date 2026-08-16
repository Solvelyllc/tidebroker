import { ActorBroker } from "../broker.js";
import type { HostActorContext } from "../core/identity.js";
import { bindTrustedRun, type TrustedWorkspaceSelection } from "../core/run-binding.js";
import type { SubjectMappingStore } from "../core/subject.js";
import type { CredentialGrant } from "../worker/grant.js";
import type { ConnectorId } from "../core/policy.js";
import { GOOGLE_CALENDAR_EVENTS_LIST_ACTION, GOOGLE_GOG_CONNECTOR_ID, validateGoogleCalendarEventsListInput, type GoogleCalendarEventsListInput } from "./google-gog.js";

export interface CredentialWorkerClient {
  execute<T = unknown>(input: { connectorId: ConnectorId; action: string; grant: CredentialGrant; input: unknown }): Promise<T>;
}

export class GoogleRuntimeBindingError extends Error {
  constructor(readonly code: "RUN_NOT_BOUND" | "REQUEST_ID_INVALID") { super(code); this.name = "GoogleRuntimeBindingError"; }
}

/**
 * Host integration seam. Identity and workspace are separate trusted arguments;
 * the model-visible input contains only Calendar operation fields.
 */
export class ActorScopedGoogleCalendarRuntime {
  constructor(readonly options: {
    subjects: SubjectMappingStore;
    workspaces: TrustedWorkspaceSelection;
    broker: ActorBroker;
    worker: CredentialWorkerClient;
  }) {}

  async listEvents<T = unknown>(hostContext: Readonly<HostActorContext>, requestId: string, rawInput: unknown): Promise<T> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(requestId)) throw new GoogleRuntimeBindingError("REQUEST_ID_INVALID");
    const operationInput: Readonly<GoogleCalendarEventsListInput> = validateGoogleCalendarEventsListInput(rawInput);
    const run = await bindTrustedRun({ hostContext, subjects: this.options.subjects, workspaces: this.options.workspaces });
    if (!run.ok) throw new GoogleRuntimeBindingError("RUN_NOT_BOUND");
    const authorized = await this.options.broker.authorize({ binding: run.binding, connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION, requestId });
    return await this.options.worker.execute<T>({ ...authorized, input: operationInput });
  }
}
