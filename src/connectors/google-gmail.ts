import type { CredentialMaterial } from "../credentials/store.js";
import type { WorkerOperation } from "../worker/worker.js";
import { runGogOAuthCommand, type GogExecutionOptions } from "./gog-executor.js";
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

export function createGoogleGmailOperations(options?: GogExecutionOptions): readonly WorkerOperation[] {
  const run = async (material: CredentialMaterial | undefined, input: Parameters<typeof runGogOAuthCommand>[2]) => {
    if (!options) throw new Error("GOG_RUNTIME_NOT_CONFIGURED");
    return await runGogOAuthCommand(options, oauth(material), input);
  };
  return Object.freeze([
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION, mutating: false, async execute({ material }, raw) {
      const input = validateGoogleGmailMessagesSearchInput(raw);
      const result = await run(material, { command: "gmail.messages.search", mutating: false, argv: ["gmail", "messages", "search", input.query ?? "in:anywhere", "--max", String(input.maxResults ?? 10)] });
      return Object.freeze({ source: "gog:gmail", untrusted: true, result });
    } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGE_GET_ACTION, mutating: false, async execute({ material }, raw) {
      const input = validateGoogleGmailMessageGetInput(raw);
      const result = await run(material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", input.messageId, "--sanitize-content"] });
      return Object.freeze({ source: "gog:gmail", untrusted: true, result });
    } },
    { connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_GMAIL_MESSAGE_SEND_ACTION, mutating: true, async execute({ material }, raw) {
      const input = validateGoogleGmailMessageSendInput(raw);
      const result = await run(material, { command: "gmail.send", mutating: true, allowGmailSend: true, stdin: input.textBody, argv: ["gmail", "send", "--to", input.to.join(","), ...(input.cc ? ["--cc", input.cc.join(",")] : []), ...(input.bcc ? ["--bcc", input.bcc.join(",")] : []), "--subject", input.subject, "--body-file", "-"] });
      return Object.freeze({ sent: true, result });
    } },
  ]);
}
