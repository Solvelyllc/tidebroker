import { canonicalPayloadDigest } from "../core/canonical.js";
import type { HostActorContext } from "../core/identity.js";

export const GOOGLE_WRITE_TOOL_NAMES = new Set(["google_calendar_event_create", "google_calendar_event_update", "google_calendar_event_delete", "google_gmail_message_send"]);

interface ApprovalTicket { readonly digest: string; readonly actor: string; readonly expiresAt: number }
const tickets = new Map<string, ApprovalTicket>();

function actor(channel: unknown, account: unknown, sender: unknown): string | null {
  if (typeof channel !== "string" || typeof sender !== "string" || sender.length === 0) return null;
  return JSON.stringify([channel, typeof account === "string" ? account : null, sender]);
}
function hostActor(context: HostActorContext): string | null { return actor(context.messageChannel, context.agentAccountId, context.requesterSenderId); }
function key(toolName: string, toolCallId: string): string { return `${toolName}\0${toolCallId}`; }
function safe(value: unknown, fallback: string): string { return typeof value === "string" && value.length > 0 ? value.replace(/[\u0000-\u001f\u007f]/gu, " ").slice(0, 120) : fallback; }

function description(toolName: string, params: Record<string, unknown>): string {
  if (toolName === "google_gmail_message_send") return `Send email to ${Array.isArray(params.to) ? params.to.filter((item): item is string => typeof item === "string").slice(0, 10).join(", ") : "(invalid recipients)"} with subject “${safe(params.subject, "(no subject)")}”. Plain-text body (${typeof params.textBody === "string" ? params.textBody.length : 0} characters):\n\n${typeof params.textBody === "string" ? params.textBody : "(invalid body)"}`;
  if (toolName === "google_calendar_event_create") return `Create Calendar event “${safe(params.summary, "(untitled)")}” from ${safe(params.start, "the supplied start")} to ${safe(params.end, "the supplied end")}.`;
  if (toolName === "google_calendar_event_update") return `Update Calendar event ${safe(params.eventId, "(invalid id)")} using exactly the proposed fields.`;
  return `Delete Calendar event ${safe(params.eventId, "(invalid id)")}.`;
}

/** Hook result for OpenClaw's durable, operator-authenticated plugin approval UI. */
export function requireGoogleWriteApproval(event: { toolName: string; toolCallId?: string; params: Record<string, unknown> }, context: { requester?: { channel?: string; accountId?: string; senderId?: string } }): unknown {
  if (!GOOGLE_WRITE_TOOL_NAMES.has(event.toolName)) return undefined;
  const approvalActor = actor(context.requester?.channel, context.requester?.accountId, context.requester?.senderId);
  if (!event.toolCallId || !approvalActor) return { block: true, blockReason: "A trusted interactive requester is required for Google writes." };
  const digest = canonicalPayloadDigest(event.params); const ticketKey = key(event.toolName, event.toolCallId);
  const emailSend = event.toolName === "google_gmail_message_send";
  return { requireApproval: { title: emailSend ? "Approve email send" : "Approve Google Calendar change", description: description(event.toolName, event.params), severity: emailSend || event.toolName === "google_calendar_event_delete" ? "critical" : "warning", timeoutMs: 5 * 60 * 1000, timeoutReason: "Google change was not approved.", allowedDecisions: ["allow-once", "deny"], pluginId: "tidebroker", onResolution: (decision: string) => { if (decision === "allow-once") tickets.set(ticketKey, { digest, actor: approvalActor, expiresAt: Date.now() + 2 * 60 * 1000 }); else tickets.delete(ticketKey); } } };
}

/** Single-use proof consumed immediately before a mutating broker grant is issued. */
export function consumeGoogleWriteApproval(toolName: string, toolCallId: string, params: unknown, context: HostActorContext): void {
  const ticketKey = key(toolName, toolCallId); const ticket = tickets.get(ticketKey); tickets.delete(ticketKey);
  const expectedActor = hostActor(context);
  if (!ticket || ticket.expiresAt <= Date.now() || !expectedActor || ticket.actor !== expectedActor || ticket.digest !== canonicalPayloadDigest(params)) throw new Error("GOOGLE_WRITE_APPROVAL_REQUIRED");
}
