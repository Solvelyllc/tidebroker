import { spawn } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { defineConnectorId } from "../core/policy.js";
import type { WorkerOperation } from "../worker/worker.js";
import type { CredentialMaterial } from "../credentials/store.js";
import type { CredentialGrantClaims } from "../worker/grant.js";
import { runGogOAuthCommand } from "./gog-executor.js";

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
export function createGoogleGogCalendarListOperation(options: {
  executablePath?: string;
  configRoot?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  fetch?: typeof fetch;
}): WorkerOperation<GoogleCalendarEventsListInput, unknown> {
  if ((options.executablePath === undefined) !== (options.configRoot === undefined) || options.executablePath !== undefined && (!isAbsolute(options.executablePath) || !isAbsolute(options.configRoot!))) throw new TypeError("gog paths must be absolute and configured together.");
  const runtime = { executablePath: options.executablePath, configRoot: options.configRoot, timeoutMs: options.timeoutMs ?? 30_000, maxOutputBytes: options.maxOutputBytes ?? 1024 * 1024 };
  return Object.freeze({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    action: GOOGLE_CALENDAR_EVENTS_LIST_ACTION,
    mutating: false,
    async execute({ material }: { readonly claims: CredentialGrantClaims; readonly material?: CredentialMaterial }, rawInput: GoogleCalendarEventsListInput) {
      if (!material) throw new Error("GOG_CREDENTIAL_KIND_MISMATCH");
      const input = validateGoogleCalendarEventsListInput(rawInput);
      if (!runtime.executablePath || !runtime.configRoot) throw new Error("GOG_RUNTIME_NOT_CONFIGURED");
      if (material.kind === "oauth2") return await runGogOAuthCommand({ ...runtime, executablePath: runtime.executablePath, configRoot: runtime.configRoot, fetch: options.fetch }, material, {
        command: "calendar.events", mutating: false,
        argv: ["calendar", "events", ...(input.today === true ? ["--today"] : []), ...(input.maxResults === undefined ? [] : ["--max", String(input.maxResults)])],
      });
      return await runGog({ ...runtime, executablePath: runtime.executablePath, configRoot: runtime.configRoot }, material.configDirectory, material.accountAlias, input);
    },
  });
}
