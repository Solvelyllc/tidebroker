import { describe, expect, it } from "vitest";
import { consumeGoogleWriteApproval, requireGoogleWriteApproval } from "./write-approval.js";
import { nonRetriableOutcomeUnknown } from "./google-write-tools.js";

const context = { requester: { channel: "webchat", accountId: "default", senderId: "sender-1" } };
const host = { messageChannel: "webchat", agentAccountId: "default", requesterSenderId: "sender-1" };

describe("Google write approvals", () => {
  it("requires an exact, single-use allow-once decision", () => {
    const params = { summary: "Review", start: "2026-08-15T15:00:00Z", end: "2026-08-15T15:30:00Z" };
    const result = requireGoogleWriteApproval({ toolName: "google_calendar_event_create", toolCallId: "call-1", params }, context) as { requireApproval: { allowedDecisions: string[]; onResolution(decision: string): void } };
    expect(result.requireApproval.allowedDecisions).toEqual(["allow-once", "deny"]);
    expect(() => consumeGoogleWriteApproval("google_calendar_event_create", "call-1", params, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
    result.requireApproval.onResolution("allow-once");
    expect(() => consumeGoogleWriteApproval("google_calendar_event_create", "call-1", { ...params, summary: "Changed" }, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
    result.requireApproval.onResolution("allow-once");
    expect(() => consumeGoogleWriteApproval("google_calendar_event_create", "call-1", params, host)).not.toThrow();
    expect(() => consumeGoogleWriteApproval("google_calendar_event_create", "call-1", params, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
  });

  it("fails closed without trusted interactive requester context", () => {
    expect(requireGoogleWriteApproval({ toolName: "google_calendar_event_delete", toolCallId: "call-2", params: { eventId: "event_12345" } }, {})).toMatchObject({ block: true });
  });

  it("binds email-send approval to the exact recipients, subject, and body", () => {
    const params = { to: ["recipient@example.com"], subject: "Approved", textBody: "Exact body" };
    const result = requireGoogleWriteApproval({ toolName: "google_gmail_message_send", toolCallId: "call-email", params }, context) as { requireApproval: { severity: string; description: string; onResolution(decision: string): void } };
    expect(result.requireApproval.severity).toBe("critical"); expect(result.requireApproval.description).toContain("Exact body"); result.requireApproval.onResolution("allow-once");
    expect(() => consumeGoogleWriteApproval("google_gmail_message_send", "call-email", { ...params, textBody: "Changed body" }, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
  });

  it("shows every Calendar field, attendee, and notification effect", () => {
    const params = { summary: "Launch", description: "Exact agenda", location: "Room 1", start: "2026-08-17T15:00:00Z", end: "2026-08-17T15:30:00Z", timeZone: "America/Indiana/Indianapolis", attendees: ["one@example.com", "two@example.com"] };
    const create = requireGoogleWriteApproval({ toolName: "google_calendar_event_create", toolCallId: "call-calendar-create", params }, context) as { requireApproval: { description: string } };
    expect(create.requireApproval.description).toContain("email invitations");
    for (const value of ["Exact agenda", "Room 1", "America/Indiana/Indianapolis", "one@example.com", "two@example.com"]) expect(create.requireApproval.description).toContain(value);

    const update = requireGoogleWriteApproval({ toolName: "google_calendar_event_update", toolCallId: "call-calendar-update", params: { eventId: "event_12345", attendees: ["new@example.com"], location: "Room 2" } }, context) as { requireApproval: { description: string } };
    expect(update.requireApproval.description).toContain("No attendee email notifications");
    expect(update.requireApproval.description).toContain("new@example.com");
    expect(update.requireApproval.description).toContain("Room 2");

    const remove = requireGoogleWriteApproval({ toolName: "google_calendar_event_delete", toolCallId: "call-calendar-delete", params: { eventId: "event_12345" } }, context) as { requireApproval: { description: string } };
    expect(remove.requireApproval.description).toContain("No attendee email notifications");
  });

  it("represents an outcome-unknown write as an explicit non-retriable result", () => {
    expect(nonRetriableOutcomeUnknown({ code: "WORKER_OUTCOME_UNKNOWN", retryable: false })).toMatchObject({ details: { outcome: "unknown", retryable: false, code: "WORKER_OUTCOME_UNKNOWN" } });
  });
});
