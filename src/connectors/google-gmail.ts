import type { CredentialMaterial } from "../credentials/store.js";
import type { WorkerOperation } from "../worker/worker.js";
import { runGogOAuthCommand } from "./gog-executor.js";
import { boundedExternalText, externalRecord, googleApiRequest, type GoogleWorkspaceExecutionOptions } from "./google-api-executor.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";

export const GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION = "gmail.messages.search" as const;
export const GOOGLE_GMAIL_MESSAGE_GET_ACTION = "gmail.messages.get" as const;
export const GOOGLE_GMAIL_MESSAGE_SEND_ACTION = "gmail.messages.send" as const;
export const GOOGLE_GMAIL_ACTIONS = [GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION, GOOGLE_GMAIL_MESSAGE_GET_ACTION, GOOGLE_GMAIL_MESSAGE_SEND_ACTION] as const;

const MESSAGE_ID = /^[A-Za-z0-9_-]{1,256}$/;
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}$/;

export interface GoogleGmailMessagesSearchInput { readonly query?: string; readonly maxResults?: number }
export interface GoogleGmailMessageGetInput { readonly messageId: string }
export interface GoogleGmailMessageSendInput { readonly to: readonly string[]; readonly cc?: readonly string[]; readonly bcc?: readonly string[]; readonly subject: string; readonly textBody: string }

function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function cleanText(value: unknown, max: number, required = false): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || value.length < (required ? 1 : 0) || value.length > max || value.includes("\0")) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  return value;
}
function messageId(value: unknown): string { if (typeof value !== "string" || !MESSAGE_ID.test(value)) throw new Error("GOOGLE_GMAIL_INPUT_INVALID"); return value; }
function addresses(value: unknown, required: boolean): readonly string[] | undefined {
  if (value === undefined && !required) return undefined;
  if (!Array.isArray(value) || value.length < (required ? 1 : 0) || value.length > 50 || value.some((item) => typeof item !== "string" || !EMAIL.test(item) || /[\r\n]/u.test(item))) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  return Object.freeze([...new Set(value as string[])]);
}

export function validateGoogleGmailMessagesSearchInput(value: unknown): Readonly<GoogleGmailMessagesSearchInput> {
  if (!plain(value) || Object.keys(value).some((key) => key !== "query" && key !== "maxResults")) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  const query = cleanText(value.query, 512);
  if (value.maxResults !== undefined && (!Number.isSafeInteger(value.maxResults) || (value.maxResults as number) < 1 || (value.maxResults as number) > 25)) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  return Object.freeze({ ...(query === undefined ? {} : { query }), ...(value.maxResults === undefined ? {} : { maxResults: value.maxResults as number }) });
}
export function validateGoogleGmailMessageGetInput(value: unknown): Readonly<GoogleGmailMessageGetInput> {
  if (!plain(value) || Object.keys(value).length !== 1) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  return Object.freeze({ messageId: messageId(value.messageId) });
}
export function validateGoogleGmailMessageSendInput(value: unknown): Readonly<GoogleGmailMessageSendInput> {
  if (!plain(value) || Object.keys(value).some((key) => !["to", "cc", "bcc", "subject", "textBody"].includes(key))) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  const to = addresses(value.to, true)!; const cc = addresses(value.cc, false); const bcc = addresses(value.bcc, false);
  const subject = cleanText(value.subject, 998, true)!; const textBody = cleanText(value.textBody, 64 * 1024, true)!;
  if (/[\r\n]/u.test(subject) || to.length + (cc?.length ?? 0) + (bcc?.length ?? 0) > 100) throw new Error("GOOGLE_GMAIL_INPUT_INVALID");
  return Object.freeze({ to, ...(cc === undefined ? {} : { cc }), ...(bcc === undefined ? {} : { bcc }), subject, textBody });
}

function oauth(material: CredentialMaterial | undefined): Extract<CredentialMaterial, { kind: "oauth2" }> { if (!material || material.kind !== "oauth2") throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH"); return material; }

function headerMap(value: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!Array.isArray(value)) return result;
  for (const item of value.slice(0, 100)) {
    const record = externalRecord(item); const name = boundedExternalText(record?.name, 64)?.toLowerCase(); const header = boundedExternalText(record?.value, 4096);
    if (name && header && ["from", "to", "cc", "subject", "date"].includes(name)) result[name] = header;
  }
  return result;
}

function decodeBody(data: unknown, remaining: number): string {
  if (typeof data !== "string" || data.length > 128 * 1024) return "";
  try { return Buffer.from(data, "base64url").toString("utf8").slice(0, remaining); } catch { return ""; }
}

function plainTextParts(value: unknown, depth = 0, state = { parts: 0, bytes: 0 }): string[] {
  if (depth > 10 || state.parts >= 64 || state.bytes >= 64 * 1024) return [];
  const part = externalRecord(value); if (!part) return [];
  state.parts += 1;
  const output: string[] = [];
  if (part.mimeType === "text/plain") {
    const body = externalRecord(part.body); const text = decodeBody(body?.data, 64 * 1024 - state.bytes);
    state.bytes += Buffer.byteLength(text, "utf8"); if (text) output.push(text);
  }
  if (Array.isArray(part.parts)) for (const child of part.parts) output.push(...plainTextParts(child, depth + 1, state));
  return output;
}

function messageProjection(value: unknown, includeBody: boolean): Readonly<Record<string, unknown>> {
  const message = externalRecord(value); const payload = externalRecord(message?.payload);
  if (!message || !payload) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const id = boundedExternalText(message.id, 256); if (!id) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const headers = headerMap(payload.headers);
  return Object.freeze({
    id,
    ...(boundedExternalText(message.threadId, 256) ? { threadId: boundedExternalText(message.threadId, 256) } : {}),
    ...(boundedExternalText(message.snippet, 4096) ? { snippet: boundedExternalText(message.snippet, 4096) } : {}),
    headers: Object.freeze(headers),
    ...(includeBody ? { textBody: plainTextParts(payload).join("\n").slice(0, 64 * 1024) } : {}),
  });
}

function encodedWord(value: string): string { return `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`; }
function mime(input: GoogleGmailMessageSendInput): string {
  return [
    `To: ${input.to.join(", ")}`,
    ...(input.cc ? [`Cc: ${input.cc.join(", ")}`] : []),
    ...(input.bcc ? [`Bcc: ${input.bcc.join(", ")}`] : []),
    `Subject: ${encodedWord(input.subject)}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from(input.textBody, "utf8").toString("base64"),
  ].join("\r\n");
}

export function createGoogleGmailOperations(options: GoogleWorkspaceExecutionOptions): readonly WorkerOperation[] {
  const run = async (material: CredentialMaterial | undefined, input: Parameters<typeof runGogOAuthCommand>[2]) => {
    if (options.backend !== "gog") throw new Error("GOOGLE_EXECUTION_BACKEND_MISMATCH");
    return await runGogOAuthCommand(options.gog, oauth(material), input);
  };
  return Object.freeze([
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION, mutating: false, async execute({ material }, raw) {
      const input = validateGoogleGmailMessagesSearchInput(raw);
      if (options.backend === "direct") {
        const query = new URLSearchParams({ q: input.query ?? "in:anywhere", maxResults: String(input.maxResults ?? 10) });
        const listing = externalRecord(await googleApiRequest(options.direct ?? {}, material, { method: "GET", path: "/gmail/v1/users/me/messages", query }));
        if (!listing || !Array.isArray(listing.messages)) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
        const messages = [];
        for (const candidate of listing.messages.slice(0, input.maxResults ?? 10)) {
          const id = boundedExternalText(externalRecord(candidate)?.id, 256); if (!id || !MESSAGE_ID.test(id)) continue;
          const metadataQuery = new URLSearchParams({ format: "metadata" }); for (const name of ["From", "Subject", "Date"]) metadataQuery.append("metadataHeaders", name);
          messages.push(messageProjection(await googleApiRequest(options.direct ?? {}, material, { method: "GET", path: `/gmail/v1/users/me/messages/${encodeURIComponent(id)}`, query: metadataQuery }), false));
        }
        return Object.freeze({ source: "google-api:gmail", untrusted: true, result: Object.freeze({ messages: Object.freeze(messages) }) });
      }
      const result = await run(material, { command: "gmail.messages.search", mutating: false, argv: ["gmail", "messages", "search", input.query ?? "in:anywhere", "--max", String(input.maxResults ?? 10)] });
      return Object.freeze({ source: "gog:gmail", untrusted: true, result });
    } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGE_GET_ACTION, mutating: false, async execute({ material }, raw) {
      const input = validateGoogleGmailMessageGetInput(raw);
      if (options.backend === "direct") return Object.freeze({ source: "google-api:gmail", untrusted: true, result: messageProjection(await googleApiRequest(options.direct ?? {}, material, { method: "GET", path: `/gmail/v1/users/me/messages/${encodeURIComponent(input.messageId)}`, query: new URLSearchParams({ format: "full" }) }), true) });
      const result = await run(material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", input.messageId, "--sanitize-content"] });
      return Object.freeze({ source: "gog:gmail", untrusted: true, result });
    } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGE_SEND_ACTION, mutating: true, async execute({ material }, raw) {
      const input = validateGoogleGmailMessageSendInput(raw);
      if (options.backend === "direct") {
        const response = externalRecord(await googleApiRequest(options.direct ?? {}, material, { method: "POST", path: "/gmail/v1/users/me/messages/send", body: { raw: Buffer.from(mime(input), "utf8").toString("base64url") } }));
        const id = boundedExternalText(response?.id, 256); if (!id) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
        return Object.freeze({ sent: true, result: Object.freeze({ id, ...(boundedExternalText(response?.threadId, 256) ? { threadId: boundedExternalText(response?.threadId, 256) } : {}) }) });
      }
      const result = await run(material, { command: "gmail.send", mutating: true, allowGmailSend: true, stdin: input.textBody, argv: ["gmail", "send", "--to", input.to.join(","), ...(input.cc ? ["--cc", input.cc.join(",")] : []), ...(input.bcc ? ["--bcc", input.bcc.join(",")] : []), "--subject", input.subject, "--body-file", "-"] });
      return Object.freeze({ sent: true, result });
    } },
  ]);
}
