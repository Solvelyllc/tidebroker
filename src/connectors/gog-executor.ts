import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, stat, type FileHandle } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { CredentialMaterial } from "../credentials/store.js";
import { googleAccessToken } from "./google-oauth.js";

export const GOG_COMMANDS = ["calendar.events", "calendar.create", "calendar.update", "calendar.delete", "gmail.messages.search", "gmail.get", "gmail.send", "drive.ls", "docs.info", "sheets.metadata"] as const;
export type GogCommand = (typeof GOG_COMMANDS)[number];

export interface GogExecutionOptions {
  readonly executablePath: string;
  readonly executableSha256: string;
  readonly configRoot: string;
  readonly httpsProxy?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly fetch?: typeof fetch;
}

const PROJECTIONS: Readonly<Record<GogCommand, string>> = Object.freeze({
  "calendar.events": "id,summary,status,start,end,location",
  "calendar.create": "id,summary,status,start,end,location",
  "calendar.update": "id,summary,status,start,end,location",
  "calendar.delete": "deleted,calendarId,eventId",
  "gmail.messages.search": "id,threadId,date,internalDateIso,from,subject,labels",
  "gmail.get": "id,threadId,labelIds,snippet,internalDate,sizeEstimate,headers,body",
  "gmail.send": "messageId,threadId",
  "drive.ls": "id,mimeType",
  "docs.info": "file.id,file.mimeType,document.documentId,document.revisionId",
  "sheets.metadata": "spreadsheetId",
});

const RESULTS_ONLY: Readonly<Record<GogCommand, boolean>> = Object.freeze({
  "calendar.events": true, "calendar.create": true, "calendar.update": true, "calendar.delete": true,
  "gmail.messages.search": true, "gmail.get": true, "gmail.send": true,
  "drive.ls": true, "docs.info": false, "sheets.metadata": false,
});

type Runtime = Readonly<Required<Omit<GogExecutionOptions, "fetch" | "httpsProxy">> & Pick<GogExecutionOptions, "fetch" | "httpsProxy">>;
function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(record: Record<string, unknown>, allowed: readonly string[]): void { const keys = new Set(allowed); if (Object.keys(record).some((key) => !keys.has(key))) throw new Error("GOG_OUTPUT_INVALID"); }
function text(value: unknown, required = false): void { if (value === undefined && !required) return; if (typeof value !== "string" || value.length > 256 * 1024 || required && value.length === 0) throw new Error("GOG_OUTPUT_INVALID"); }
function stringList(value: unknown): void { if (!Array.isArray(value) || value.length > 10_000 || value.some((item) => typeof item !== "string" || item.length > 16 * 1024)) throw new Error("GOG_OUTPUT_INVALID"); }
function externalContent(value: unknown): void { if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["untrusted", "source", "wrapped"]); if (value.untrusted !== true || value.source !== "google_api" || value.wrapped !== true) throw new Error("GOG_OUTPUT_INVALID"); }
function dateTime(value: unknown): void { if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["date", "dateTime", "timeZone"]); text(value.date); text(value.dateTime); text(value.timeZone); if (value.date === undefined && value.dateTime === undefined) throw new Error("GOG_OUTPUT_INVALID"); }
function event(value: unknown): void { if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["id", "summary", "status", "start", "end", "location", "externalContent"]); text(value.id, true); text(value.summary); text(value.status); text(value.location); if (value.start !== undefined) dateTime(value.start); if (value.end !== undefined) dateTime(value.end); if (value.externalContent !== undefined) externalContent(value.externalContent); }
function headers(value: unknown): void { if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["from", "to", "cc", "bcc", "subject", "date", "message_id", "in_reply_to", "references"]); for (const child of Object.values(value)) text(child); }

/** Parses only the fields selected for a specific command and rejects every unknown field. */
export function parseGogOutput(command: GogCommand, value: unknown, accessToken?: string): unknown {
  if (accessToken && JSON.stringify(value).includes(accessToken)) throw new Error("GOG_OUTPUT_INVALID");
  switch (command) {
    case "calendar.events": if (!Array.isArray(value) || value.length > 10_000) throw new Error("GOG_OUTPUT_INVALID"); value.forEach(event); break;
    case "calendar.create": case "calendar.update": event(value); break;
    case "calendar.delete": if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["deleted", "calendarId", "eventId"]); if (value.deleted !== true) throw new Error("GOG_OUTPUT_INVALID"); text(value.calendarId, true); text(value.eventId, true); break;
    case "gmail.messages.search":
      if (!Array.isArray(value) || value.length > 10_000) throw new Error("GOG_OUTPUT_INVALID");
      for (const item of value) { if (!plain(item)) throw new Error("GOG_OUTPUT_INVALID"); exact(item, ["id", "threadId", "date", "internalDateIso", "from", "subject", "labels", "externalContent"]); text(item.id, true); text(item.threadId); text(item.date); text(item.internalDateIso); text(item.from); text(item.subject); if (item.labels !== undefined) stringList(item.labels); if (item.externalContent !== undefined) externalContent(item.externalContent); }
      break;
    case "gmail.get": {
      if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID");
      let message = value;
      if (value.message !== undefined) {
        exact(value, ["message", "headers", "body", "externalContent"]);
        if (value.externalContent !== undefined) externalContent(value.externalContent);
        if (!plain(value.message)) throw new Error("GOG_OUTPUT_INVALID");
        message = value.message;
      }
      exact(message, ["id", "threadId", "labelIds", "snippet", "internalDate", "sizeEstimate", "headers", "body", "attachments", "externalContent"]);
      text(message.id, true); text(message.threadId); text(message.snippet); text(message.body);
      if (message.labelIds !== undefined) stringList(message.labelIds);
      if (message.internalDate !== undefined && (!Number.isSafeInteger(message.internalDate) || (message.internalDate as number) < 0) || message.sizeEstimate !== undefined && (!Number.isSafeInteger(message.sizeEstimate) || (message.sizeEstimate as number) < 0)) throw new Error("GOG_OUTPUT_INVALID");
      if (message.headers !== undefined) headers(message.headers);
      if (message.attachments !== undefined && (!Array.isArray(message.attachments) || message.attachments.length > 10_000)) throw new Error("GOG_OUTPUT_INVALID");
      if (message.externalContent !== undefined) externalContent(message.externalContent);
      return Object.freeze({
        id: message.id,
        ...(message.threadId === undefined ? {} : { threadId: message.threadId }),
        ...(message.labelIds === undefined ? {} : { labelIds: message.labelIds }),
        ...(message.snippet === undefined ? {} : { snippet: message.snippet }),
        ...(message.internalDate === undefined ? {} : { internalDate: message.internalDate }),
        ...(message.sizeEstimate === undefined ? {} : { sizeEstimate: message.sizeEstimate }),
        ...(message.headers === undefined ? {} : { headers: message.headers }),
        ...(message.body === undefined ? {} : { body: message.body }),
        ...(message.externalContent === undefined ? {} : { externalContent: message.externalContent }),
      });
    }
    case "gmail.send": if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["messageId", "threadId"]); text(value.messageId, true); text(value.threadId); break;
    case "drive.ls":
      if (!Array.isArray(value) || value.length > 100) throw new Error("GOG_OUTPUT_INVALID");
      for (const item of value) { if (!plain(item)) throw new Error("GOG_OUTPUT_INVALID"); exact(item, ["id", "mimeType"]); text(item.id, true); text(item.mimeType, true); }
      break;
    case "docs.info":
      if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID");
      exact(value, ["file.id", "file.mimeType", "document.documentId", "document.revisionId"]);
      text(value["file.id"], true); text(value["file.mimeType"], true); text(value["document.documentId"], true); text(value["document.revisionId"]);
      break;
    case "sheets.metadata":
      if (!plain(value)) throw new Error("GOG_OUTPUT_INVALID"); exact(value, ["spreadsheetId"]); text(value.spreadsheetId, true); break;
  }
  return value;
}

export function validateGogExecutionOptions(options: GogExecutionOptions): Runtime {
  if (!isAbsolute(options.executablePath) || !isAbsolute(options.configRoot) || !/^[a-f0-9]{64}$/.test(options.executableSha256)) throw new TypeError("gog paths and digest must be pinned.");
  if (options.httpsProxy !== undefined) {
    let proxy: URL;
    try { proxy = new URL(options.httpsProxy); } catch { throw new TypeError("gog HTTPS proxy must be an explicit loopback URL."); }
    if (proxy.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(proxy.hostname) || proxy.port === "" || Number(proxy.port) < 1 || Number(proxy.port) > 65_535 || proxy.username !== "" || proxy.password !== "" || proxy.pathname !== "/" || proxy.search !== "" || proxy.hash !== "") throw new TypeError("gog HTTPS proxy must be an explicit loopback URL.");
  }
  const timeoutMs = options.timeoutMs ?? 30_000; const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000 || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1024 || maxOutputBytes > 4 * 1024 * 1024) throw new TypeError("gog limits are invalid.");
  return Object.freeze({ ...options, timeoutMs, maxOutputBytes });
}

async function openVerifiedGogExecutable(runtime: Pick<Runtime, "executablePath" | "executableSha256">): Promise<FileHandle> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(runtime.executablePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o100) === 0 || (info.mode & 0o022) !== 0 ||
      typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("GOG_EXECUTABLE_INVALID");
    const digest = createHash("sha256").update(await handle.readFile()).digest("hex");
    if (digest !== runtime.executableSha256) throw new Error("GOG_EXECUTABLE_INVALID");
    return handle;
  } catch {
    await handle?.close();
    throw new Error("GOG_EXECUTABLE_INVALID");
  }
}

/** Executes one baked/allowlisted gog command with a closed environment. */
export async function runGogOAuthCommand(options: GogExecutionOptions, material: Extract<CredentialMaterial, { kind: "oauth2" }>, input: {
  readonly command: GogCommand; readonly argv: readonly string[]; readonly mutating: boolean; readonly allowGmailSend?: boolean; readonly stdin?: string; readonly assertCredentialActive: () => Promise<void>; readonly markProviderCallStarted: () => void;
}): Promise<unknown> {
  const runtime = validateGogExecutionOptions(options);
  if (!GOG_COMMANDS.includes(input.command) || input.argv.some((part) => typeof part !== "string" || part.includes("\0"))) throw new Error("GOG_COMMAND_INVALID");
  if (input.command === "gmail.send" && input.allowGmailSend !== true || input.command !== "gmail.send" && input.allowGmailSend === true) throw new Error("GOG_COMMAND_INVALID");
  const home = await realpath(runtime.configRoot); const homeStat = await stat(home);
  if (!homeStat.isDirectory()) throw new Error("GOG_RUNTIME_INVALID");
  if (process.platform !== "linux") throw new Error("GOG_RUNTIME_INVALID");
  const executable = await openVerifiedGogExecutable(runtime);
  try {
    const accessToken = await googleAccessToken(material, runtime.fetch ?? fetch);
    await input.assertCredentialActive();
    input.markProviderCallStarted();
    const argv = ["--enable-commands-exact", input.command, ...(input.mutating ? [] : ["--readonly"]), ...(input.allowGmailSend === true ? [] : ["--gmail-no-send"]), "--no-input", "--wrap-untrusted", "--json", ...(RESULTS_ONLY[input.command] ? ["--results-only"] : []), "--select", PROJECTIONS[input.command], ...input.argv];
    const executableFdPath = "/proc/self/fd/3";
    return await new Promise((resolve, reject) => {
      const env: NodeJS.ProcessEnv = { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", GOG_HOME: home, GOG_ACCESS_TOKEN: accessToken, ...(runtime.httpsProxy === undefined ? {} : { HTTPS_PROXY: runtime.httpsProxy, NO_PROXY: "127.0.0.1,::1,localhost" }) };
      const child = spawn(executableFdPath, argv, { cwd: home, env, shell: false, stdio: [input.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe", executable.fd], windowsHide: true, detached: true });
      const chunks: Buffer[] = []; let bytes = 0; let terminal = "GOG_EXECUTION_FAILED"; let settled = false;
      const stop = (code: string) => { terminal = code; if (child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); return; } catch {} } child.kill("SIGKILL"); };
      const timer = setTimeout(() => stop("GOG_TIMEOUT"), runtime.timeoutMs); timer.unref();
      const count = (chunk: Buffer, retain: boolean) => { bytes += chunk.length; if (bytes > runtime.maxOutputBytes) stop("GOG_OUTPUT_LIMIT"); else if (retain) chunks.push(chunk); };
      child.stdout!.on("data", (chunk: Buffer) => count(chunk, true)); child.stderr!.on("data", (chunk: Buffer) => count(chunk, false)); child.on("error", () => stop("GOG_EXECUTION_FAILED"));
      child.on("close", (exitCode) => { clearTimeout(timer); if (settled) return; settled = true; if (exitCode !== 0) { reject(new Error(terminal)); return; } try { resolve(parseGogOutput(input.command, JSON.parse(Buffer.concat(chunks).toString("utf8")), accessToken)); } catch { reject(new Error("GOG_OUTPUT_INVALID")); } });
      if (input.stdin !== undefined && child.stdin) { child.stdin.on("error", () => stop("GOG_EXECUTION_FAILED")); child.stdin.end(input.stdin, "utf8"); }
    });
  } finally { await executable.close(); }
}
