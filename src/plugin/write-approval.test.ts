import { describe, expect, it } from "vitest";
import { consumeGoogleWriteApproval, requireGoogleWriteApproval } from "./write-approval.js";

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

  it("requires critical exact approval for project API changes", () => {
    const params = { services: ["drive.googleapis.com"] };
    const result = requireGoogleWriteApproval({ toolName: "google_project_services_enable", toolCallId: "call-admin", params }, context) as { requireApproval: { severity: string; allowedDecisions: string[]; onResolution(decision: string): void } };
    expect(result.requireApproval.severity).toBe("critical"); expect(result.requireApproval.allowedDecisions).toEqual(["allow-once", "deny"]);
    result.requireApproval.onResolution("allow-once");
    expect(() => consumeGoogleWriteApproval("google_project_services_enable", "call-admin", { services: ["gmail.googleapis.com"] }, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
  });

  it("binds email-send approval to the exact recipients, subject, and body", () => {
    const params = { to: ["recipient@example.com"], subject: "Approved", textBody: "Exact body" };
    const result = requireGoogleWriteApproval({ toolName: "google_gmail_message_send", toolCallId: "call-email", params }, context) as { requireApproval: { severity: string; onResolution(decision: string): void } };
    expect(result.requireApproval.severity).toBe("critical"); result.requireApproval.onResolution("allow-once");
    expect(() => consumeGoogleWriteApproval("google_gmail_message_send", "call-email", { ...params, textBody: "Changed body" }, host)).toThrow("GOOGLE_WRITE_APPROVAL_REQUIRED");
  });
});
