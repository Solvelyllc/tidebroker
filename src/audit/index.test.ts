import { describe, expect, it } from "vitest";
import { buildAuditEvent } from "./index.js";

const validInput = () => ({
  actor: { id: "usr_01JTEST", kind: "human" as const },
  workspace: "ws_solvely",
  connector: "google",
  action: "calendar.events.list",
  outcome: "succeeded" as const,
  correlation: { requestId: "req_01JTEST", conversationId: "conv_01JTEST" },
  reasonCode: "POLICY_ALLOWED",
});

describe("buildAuditEvent", () => {
  it("builds a stable closed-schema event", () => {
    const event = buildAuditEvent(validInput(), {
      newEventId: () => "evt_01JTEST",
      now: () => new Date("2026-08-15T12:00:00.000Z"),
    });

    expect(event).toEqual({
      schemaVersion: "1",
      eventId: "evt_01JTEST",
      occurredAt: "2026-08-15T12:00:00.000Z",
      actor: { id: "usr_01JTEST", kind: "human" },
      workspace: "ws_solvely",
      connector: "google",
      action: "calendar.events.list",
      outcome: "succeeded",
      correlation: { requestId: "req_01JTEST", conversationId: "conv_01JTEST" },
      reasonCode: "POLICY_ALLOWED",
    });
    expect(Object.isFrozen(event)).toBe(true);
    expect(Object.isFrozen(event.actor)).toBe(true);
    expect(Object.isFrozen(event.correlation)).toBe(true);
  });

  it("rejects unknown top-level fields instead of logging them", () => {
    const input = { ...validInput(), accessToken: "must-not-be-logged" };
    expect(() => buildAuditEvent(input, { newEventId: () => "evt_1" })).toThrow(
      "unsupported field: accessToken",
    );
  });

  it("rejects unknown nested fields", () => {
    const input = {
      ...validInput(),
      actor: { ...validInput().actor, authorization: "must-not-be-logged" },
    };
    expect(() => buildAuditEvent(input, { newEventId: () => "evt_1" })).toThrow(
      "unsupported field: authorization",
    );
  });

  it("rejects free-form values and direct identifiers such as email addresses", () => {
    expect(() =>
      buildAuditEvent(
        { ...validInput(), actor: { id: "person@example.com", kind: "human" } },
        { newEventId: () => "evt_1" },
      ),
    ).toThrow("actor.id must be an opaque identifier");
    expect(() =>
      buildAuditEvent(
        { ...validInput(), reasonCode: "provider said token=secret" },
        { newEventId: () => "evt_1" },
      ),
    ).toThrow("reasonCode must be an enumerated");
  });
});
