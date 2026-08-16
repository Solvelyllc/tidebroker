import { isAbsolute } from "node:path";
import { defineConnectorId } from "../core/policy.js";
import type { WorkerOperation } from "../worker/worker.js";
import type { CredentialMaterial } from "../credentials/store.js";
import type { CredentialGrantClaims } from "../worker/grant.js";
import { runGogOAuthCommand } from "./gog-executor.js";
import { boundedExternalText, externalRecord, googleApiRequest, type GoogleWorkspaceExecutionOptions } from "./google-api-executor.js";

export const GOOGLE_GOG_CONNECTOR_ID = defineConnectorId("google-gog");
export const GOOGLE_CALENDAR_EVENTS_LIST_ACTION = "calendar.events.list" as const;

export interface GoogleCalendarEventsListInput {
  readonly today?: boolean;
  readonly maxResults?: number;
}

export function validateGoogleCalendarEventsListInput(value: unknown): Readonly<GoogleCalendarEventsListInput> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("GOG_INPUT_INVALID");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "today" && key !== "maxResults")) throw new Error("GOG_INPUT_INVALID");
  if (record.today !== undefined && typeof record.today !== "boolean") throw new Error("GOG_INPUT_INVALID");
  if (record.maxResults !== undefined && (!Number.isSafeInteger(record.maxResults) || (record.maxResults as number) < 1 || (record.maxResults as number) > 100)) throw new Error("GOG_INPUT_INVALID");
  return Object.freeze({ ...(record.today === undefined ? {} : { today: record.today as boolean }), ...(record.maxResults === undefined ? {} : { maxResults: record.maxResults as number }) });
}

function directCalendarEvent(value: unknown): Record<string, unknown> | null {
  const event = externalRecord(value); if (!event) return null;
  const start = externalRecord(event.start); const end = externalRecord(event.end);
  const id = boundedExternalText(event.id, 1024); if (!id) return null;
  return Object.freeze({
    id,
    ...(boundedExternalText(event.status, 32) ? { status: boundedExternalText(event.status, 32) } : {}),
    ...(boundedExternalText(event.summary, 1024) ? { summary: boundedExternalText(event.summary, 1024) } : {}),
    ...(boundedExternalText(event.description, 8192) ? { description: boundedExternalText(event.description, 8192) } : {}),
    ...(boundedExternalText(event.location, 1024) ? { location: boundedExternalText(event.location, 1024) } : {}),
    ...(start ? { start: Object.freeze({ ...(boundedExternalText(start.dateTime, 64) ? { dateTime: boundedExternalText(start.dateTime, 64) } : {}), ...(boundedExternalText(start.date, 16) ? { date: boundedExternalText(start.date, 16) } : {}), ...(boundedExternalText(start.timeZone, 128) ? { timeZone: boundedExternalText(start.timeZone, 128) } : {}) }) } : {}),
    ...(end ? { end: Object.freeze({ ...(boundedExternalText(end.dateTime, 64) ? { dateTime: boundedExternalText(end.dateTime, 64) } : {}), ...(boundedExternalText(end.date, 16) ? { date: boundedExternalText(end.date, 16) } : {}), ...(boundedExternalText(end.timeZone, 128) ? { timeZone: boundedExternalText(end.timeZone, 128) } : {}) }) } : {}),
  });
}

async function runDirect(material: CredentialMaterial | undefined, options: import("./google-api-executor.js").GoogleDirectExecutionOptions, input: GoogleCalendarEventsListInput, assertCredentialActive: () => Promise<void>, markProviderCallStarted: () => void): Promise<unknown> {
  const query = new URLSearchParams({ singleEvents: "true", orderBy: "startTime", maxResults: String(input.maxResults ?? 10) });
  if (input.today === true) {
    const now = new Date(); const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())); const end = new Date(start.getTime() + 86_400_000);
    query.set("timeMin", start.toISOString()); query.set("timeMax", end.toISOString());
  }
  const response = externalRecord(await googleApiRequest(options, material, { method: "GET", path: "/calendar/v3/calendars/primary/events", query, assertCredentialActive, markProviderCallStarted }));
  if (!response || !Array.isArray(response.items)) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const items = response.items.slice(0, input.maxResults ?? 10).map(directCalendarEvent).filter((item): item is Record<string, unknown> => item !== null);
  return Object.freeze({ source: "google-api:calendar", untrusted: true, items: Object.freeze(items) });
}

/** First connector surface: one exact, read-only Calendar operation. */
export function createGoogleGogCalendarListOperation(options: GoogleWorkspaceExecutionOptions): WorkerOperation<GoogleCalendarEventsListInput, unknown> {
  if (options.backend === "gog" && (!isAbsolute(options.gog.executablePath) || !isAbsolute(options.gog.configRoot) || !/^[a-f0-9]{64}$/.test(options.gog.executableSha256))) throw new TypeError("gog paths and digest must be configured together.");
  return Object.freeze({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION,
    mutating: false,
    async execute({ material, assertCredentialActive, markProviderCallStarted }: { readonly claims: CredentialGrantClaims; readonly material?: CredentialMaterial; readonly assertCredentialActive: () => Promise<void>; readonly markProviderCallStarted: () => void }, rawInput: GoogleCalendarEventsListInput) {
      if (!material) throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH");
      const input = validateGoogleCalendarEventsListInput(rawInput);
      if (options.backend === "direct") return await runDirect(material, options.direct ?? {}, input, assertCredentialActive, markProviderCallStarted);
      if (material.kind === "oauth2") return await runGogOAuthCommand(options.gog, material, {
        command: "calendar.events", mutating: false,
        argv: ["calendar", "events", ...(input.today === true ? ["--today"] : []), ...(input.maxResults === undefined ? [] : ["--max", String(input.maxResults)])],
        assertCredentialActive,
        markProviderCallStarted,
      });
      throw new Error("GOG_CREDENTIAL_KIND_MISMATCH");
    },
  });
}
