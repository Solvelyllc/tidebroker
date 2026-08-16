import { spawn } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
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

const SECRET_FIELD = /(?:^|_)(?:access_?token|api_?key|authorization|client_?secret|credentials?|password|private_?key|refresh_?token|secret|token)(?:$|_)/i;

function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 20) throw new Error("GOG_OUTPUT_INVALID");
  if (Array.isArray(value)) return value.map((item) => sanitize(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (!SECRET_FIELD.test(key)) output[key] = sanitize(child, depth + 1);
    }
    return output;
  }
  return value;
}

function isWithin(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!child.startsWith("..") && !isAbsolute(child));
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

async function runDirect(material: CredentialMaterial | undefined, options: import("./google-api-executor.js").GoogleDirectExecutionOptions, input: GoogleCalendarEventsListInput): Promise<unknown> {
  const query = new URLSearchParams({ singleEvents: "true", orderBy: "startTime", maxResults: String(input.maxResults ?? 10) });
  if (input.today === true) {
    const now = new Date(); const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())); const end = new Date(start.getTime() + 86_400_000);
    query.set("timeMin", start.toISOString()); query.set("timeMax", end.toISOString());
  }
  const response = externalRecord(await googleApiRequest(options, material, { method: "GET", path: "/calendar/v3/calendars/primary/events", query }));
  if (!response || !Array.isArray(response.items)) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const items = response.items.slice(0, input.maxResults ?? 10).map(directCalendarEvent).filter((item): item is Record<string, unknown> => item !== null);
  return Object.freeze({ source: "google-api:calendar", untrusted: true, items: Object.freeze(items) });
}

async function runGog(options: { executablePath: string; configRoot: string; timeoutMs: number; maxOutputBytes: number }, configDirectory: string, accountAlias: string, input: GoogleCalendarEventsListInput): Promise<unknown> {
  const [root, directory] = await Promise.all([realpath(options.configRoot), realpath(configDirectory)]);
  const directoryStat = await stat(directory);
  if (!directoryStat.isDirectory() || !isWithin(root, directory)) throw new Error("GOG_PROFILE_INVALID");
  if (!/^acct_[A-Za-z0-9_-]{8,96}$/.test(accountAlias)) throw new Error("GOG_PROFILE_INVALID");
  const argv = [
    "--account", accountAlias,
    "--enable-commands-exact", "calendar.events",
    "--gmail-no-send", "--readonly", "--no-input", "--wrap-untrusted", "--json",
    "calendar", "events",
    ...(input.today === true ? ["--today"] : []),
    ...(input.maxResults === undefined ? [] : ["--max", String(input.maxResults)]),
  ];
  return await new Promise((resolve, reject) => {
    const child = spawn(options.executablePath, argv, {
      cwd: directory,
      env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", GOG_HOME: directory },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: process.platform !== "win32",
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let terminal = "GOG_EXECUTION_FAILED";
    const stop = (code: string) => {
      terminal = code;
      if (process.platform !== "win32" && child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); return; } catch {} }
      child.kill("SIGKILL");
    };
    const timer = setTimeout(() => stop("GOG_TIMEOUT"), options.timeoutMs);
    timer.unref();
    child.stdout.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > options.maxOutputBytes) stop("GOG_OUTPUT_LIMIT"); else chunks.push(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > options.maxOutputBytes) stop("GOG_OUTPUT_LIMIT"); });
    child.on("error", () => stop("GOG_EXECUTION_FAILED"));
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      if (exitCode !== 0) { reject(new Error(terminal)); return; }
      try { resolve(sanitize(JSON.parse(Buffer.concat(chunks).toString("utf8")))); }
      catch { reject(new Error("GOG_OUTPUT_INVALID")); }
    });
  });
}

/** First connector surface: one exact, read-only Calendar operation. */
export function createGoogleGogCalendarListOperation(options: GoogleWorkspaceExecutionOptions): WorkerOperation<GoogleCalendarEventsListInput, unknown> {
  if (options.backend === "gog" && (!isAbsolute(options.gog.executablePath) || !isAbsolute(options.gog.configRoot))) throw new TypeError("gog paths must be absolute.");
  const runtime = options.backend === "gog" ? { executablePath: options.gog.executablePath, configRoot: options.gog.configRoot, timeoutMs: options.gog.timeoutMs ?? 30_000, maxOutputBytes: options.gog.maxOutputBytes ?? 1024 * 1024 } : null;
  return Object.freeze({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION,
    mutating: false,
    async execute({ material }: { readonly claims: CredentialGrantClaims; readonly material?: CredentialMaterial }, rawInput: GoogleCalendarEventsListInput) {
      if (!material) throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH");
      const input = validateGoogleCalendarEventsListInput(rawInput);
      if (options.backend === "direct") return await runDirect(material, options.direct ?? {}, input);
      if (!runtime) throw new Error("GOG_RUNTIME_NOT_CONFIGURED");
      if (material.kind === "oauth2") return await runGogOAuthCommand({ ...runtime, executablePath: runtime.executablePath, configRoot: runtime.configRoot, fetch: options.gog.fetch }, material, {
        command: "calendar.events", mutating: false,
        argv: ["calendar", "events", ...(input.today === true ? ["--today"] : []), ...(input.maxResults === undefined ? [] : ["--max", String(input.maxResults)])],
      });
      return await runGog(runtime, material.configDirectory, material.accountAlias, input);
    },
  });
}
