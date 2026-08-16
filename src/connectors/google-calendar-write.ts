import type { CredentialMaterial } from "../credentials/store.js";
import type { CredentialGrantClaims } from "../worker/grant.js";
import type { WorkerOperation } from "../worker/worker.js";
import { runGogOAuthCommand } from "./gog-executor.js";
import { boundedExternalText, externalRecord, googleApiRequest, type GoogleWorkspaceExecutionOptions } from "./google-api-executor.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";

export const GOOGLE_CALENDAR_EVENT_CREATE_ACTION = "calendar.events.create" as const;
export const GOOGLE_CALENDAR_EVENT_UPDATE_ACTION = "calendar.events.update" as const;
export const GOOGLE_CALENDAR_EVENT_DELETE_ACTION = "calendar.events.delete" as const;
export const GOOGLE_CALENDAR_WRITE_ACTIONS = [GOOGLE_CALENDAR_EVENT_CREATE_ACTION, GOOGLE_CALENDAR_EVENT_UPDATE_ACTION, GOOGLE_CALENDAR_EVENT_DELETE_ACTION] as const;

const EVENT_ID = /^[A-Za-z0-9_-]{5,1024}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const TIME_ZONE = /^[A-Za-z0-9_+.-]+(?:\/[A-Za-z0-9_+.-]+)*$/;

export interface CalendarEventFields {
  readonly summary?: string;
  readonly description?: string;
  readonly location?: string;
  readonly start?: string;
  readonly end?: string;
  readonly timeZone?: string;
  readonly attendees?: readonly string[];
}
export interface GoogleCalendarEventCreateInput extends CalendarEventFields { readonly summary: string; readonly start: string; readonly end: string }
export interface GoogleCalendarEventUpdateInput extends CalendarEventFields { readonly eventId: string }
export interface GoogleCalendarEventDeleteInput { readonly eventId: string }

function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function text(value: unknown, max: number, required = false): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  return value;
}
function eventId(value: unknown): string { if (typeof value !== "string" || !EVENT_ID.test(value)) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID"); return value; }
function dateTime(value: unknown): string { if (typeof value !== "string" || !RFC3339.test(value) || !Number.isFinite(Date.parse(value))) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID"); return value; }

function fields(record: Record<string, unknown>, requireCore: boolean): CalendarEventFields {
  const summary = text(record.summary, 1024, requireCore);
  const description = text(record.description, 8192);
  const location = text(record.location, 1024);
  const start = record.start === undefined && !requireCore ? undefined : dateTime(record.start);
  const end = record.end === undefined && !requireCore ? undefined : dateTime(record.end);
  if (start !== undefined && end !== undefined && Date.parse(end) <= Date.parse(start)) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  if ((start === undefined) !== (end === undefined)) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  const timeZone = record.timeZone === undefined ? undefined : text(record.timeZone, 128);
  if (timeZone !== undefined && !TIME_ZONE.test(timeZone)) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  let attendees: readonly string[] | undefined;
  if (record.attendees !== undefined) {
    if (!Array.isArray(record.attendees) || record.attendees.length > 100 || record.attendees.some((item) => typeof item !== "string" || !EMAIL.test(item))) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
    attendees = Object.freeze([...new Set(record.attendees as string[])]);
  }
  return Object.freeze({ ...(summary === undefined ? {} : { summary }), ...(description === undefined ? {} : { description }), ...(location === undefined ? {} : { location }), ...(start === undefined ? {} : { start }), ...(end === undefined ? {} : { end }), ...(timeZone === undefined ? {} : { timeZone }), ...(attendees === undefined ? {} : { attendees }) });
}

export function validateGoogleCalendarEventCreateInput(value: unknown): Readonly<GoogleCalendarEventCreateInput> {
  if (!plain(value) || Object.keys(value).some((key) => !["summary", "description", "location", "start", "end", "timeZone", "attendees"].includes(key))) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  return fields(value, true) as Readonly<GoogleCalendarEventCreateInput>;
}
export function validateGoogleCalendarEventUpdateInput(value: unknown): Readonly<GoogleCalendarEventUpdateInput> {
  if (!plain(value) || Object.keys(value).some((key) => !["eventId", "summary", "description", "location", "start", "end", "timeZone", "attendees"].includes(key))) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  const id = eventId(value.eventId); const patch = fields(value, false);
  if (Object.keys(patch).length === 0) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  return Object.freeze({ eventId: id, ...patch });
}
export function validateGoogleCalendarEventDeleteInput(value: unknown): Readonly<GoogleCalendarEventDeleteInput> {
  if (!plain(value) || Object.keys(value).length !== 1) throw new Error("GOOGLE_CALENDAR_INPUT_INVALID");
  return Object.freeze({ eventId: eventId(value.eventId) });
}

function oauth(material: CredentialMaterial | undefined): Extract<CredentialMaterial, { kind: "oauth2" }> { if (!material || material.kind !== "oauth2") throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH"); return material; }
function fieldArgs(input: CalendarEventFields): string[] {
  return [
    ...(input.summary === undefined ? [] : ["--summary", input.summary]),
    ...(input.description === undefined ? [] : ["--description", input.description]),
    ...(input.location === undefined ? [] : ["--location", input.location]),
    ...(input.start === undefined ? [] : ["--from", input.start]),
    ...(input.end === undefined ? [] : ["--to", input.end]),
    ...(input.timeZone === undefined ? [] : ["--timezone", input.timeZone]),
    ...(input.attendees === undefined ? [] : ["--attendees", input.attendees.join(",")]),
  ];
}

function directBody(input: CalendarEventFields): Record<string, unknown> {
  return {
    ...(input.summary === undefined ? {} : { summary: input.summary }),
    ...(input.description === undefined ? {} : { description: input.description }),
    ...(input.location === undefined ? {} : { location: input.location }),
    ...(input.start === undefined ? {} : { start: { dateTime: input.start, ...(input.timeZone === undefined ? {} : { timeZone: input.timeZone }) } }),
    ...(input.end === undefined ? {} : { end: { dateTime: input.end, ...(input.timeZone === undefined ? {} : { timeZone: input.timeZone }) } }),
    ...(input.attendees === undefined ? {} : { attendees: input.attendees.map((email) => ({ email })) }),
  };
}

function directResult(value: unknown): Readonly<Record<string, unknown>> {
  const record = externalRecord(value);
  if (!record) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const id = boundedExternalText(record.id, 1024);
  if (!id) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  return Object.freeze({
    source: "google-api:calendar",
    untrusted: true,
    result: Object.freeze({ id, ...(boundedExternalText(record.status, 32) ? { status: boundedExternalText(record.status, 32) } : {}), ...(boundedExternalText(record.updated, 64) ? { updated: boundedExternalText(record.updated, 64) } : {}) }),
  });
}

export function createGoogleCalendarWriteOperations(options: GoogleWorkspaceExecutionOptions): readonly WorkerOperation[] {
  const execute = async (material: CredentialMaterial | undefined, assertCredentialActive: () => Promise<void>, markProviderCallStarted: () => void, command: "calendar.create" | "calendar.update" | "calendar.delete", argv: readonly string[]) => {
    if (options.backend !== "gog") throw new Error("GOOGLE_EXECUTION_BACKEND_MISMATCH");
    return await runGogOAuthCommand(options.gog, oauth(material), { command, mutating: true, argv, assertCredentialActive, markProviderCallStarted });
  };
  return Object.freeze([
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENT_CREATE_ACTION, mutating: true, async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) { const input = validateGoogleCalendarEventCreateInput(raw); if (options.backend === "direct") return directResult(await googleApiRequest(options.direct ?? {}, material, { method: "POST", path: "/calendar/v3/calendars/primary/events", query: new URLSearchParams({ sendUpdates: "all" }), body: directBody(input), assertCredentialActive, markProviderCallStarted })); return await execute(material, assertCredentialActive, markProviderCallStarted, "calendar.create", ["calendar", "create", "primary", ...fieldArgs(input), "--send-updates", "all"]); } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENT_UPDATE_ACTION, mutating: true, async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) { const input = validateGoogleCalendarEventUpdateInput(raw); if (options.backend === "direct") return directResult(await googleApiRequest(options.direct ?? {}, material, { method: "PATCH", path: `/calendar/v3/calendars/primary/events/${encodeURIComponent(input.eventId)}`, query: new URLSearchParams({ sendUpdates: "all" }), body: directBody(input), assertCredentialActive, markProviderCallStarted })); return await execute(material, assertCredentialActive, markProviderCallStarted, "calendar.update", ["calendar", "update", "primary", input.eventId, ...fieldArgs(input), "--send-updates", "all"]); } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_CALENDAR_EVENT_DELETE_ACTION, mutating: true, async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) { const input = validateGoogleCalendarEventDeleteInput(raw); if (options.backend === "direct") { await googleApiRequest(options.direct ?? {}, material, { method: "DELETE", path: `/calendar/v3/calendars/primary/events/${encodeURIComponent(input.eventId)}`, query: new URLSearchParams({ sendUpdates: "all" }), allowEmpty: true, assertCredentialActive, markProviderCallStarted }); return Object.freeze({ deleted: true }); } return await execute(material, assertCredentialActive, markProviderCallStarted, "calendar.delete", ["calendar", "delete", "primary", input.eventId, "--send-updates", "all", "--force"]); } },
  ]);
}
