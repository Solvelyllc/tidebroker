import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleCalendarWriteOperations, GOOGLE_CALENDAR_EVENT_CREATE_ACTION, validateGoogleCalendarEventUpdateInput } from "./google-calendar-write.js";

describe("Google Calendar gog write connector", () => {
  it("validates updates and invokes the exact baked gog create command", async () => {
    expect(() => validateGoogleCalendarEventUpdateInput({ eventId: "event_12345" })).toThrow("GOOGLE_CALENDAR_INPUT_INVALID");
    const root = await mkdtemp(join(tmpdir(), "calendar-gog-"));
    const executablePath = await createFakeGog(root);
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));
    const operation = createGoogleCalendarWriteOperations({ executablePath, configRoot: root, fetch: fetcher as typeof fetch }).find((item) => item.action === GOOGLE_CALENDAR_EVENT_CREATE_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "refresh-canary", clientId: "client-id" } }, { summary: "Approved event", start: "2026-08-15T15:00:00Z", end: "2026-08-15T15:30:00Z" }) as { argv: string[]; hasAccessToken: boolean; access_token?: string };
    expect(output.argv).toEqual(["--enable-commands-exact", "calendar.create", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "calendar", "create", "primary", "--summary", "Approved event", "--from", "2026-08-15T15:00:00Z", "--to", "2026-08-15T15:30:00Z", "--send-updates", "all"]);
    expect(output.hasAccessToken).toBe(true); expect(output.access_token).toBeUndefined(); expect(JSON.stringify(output)).not.toContain("access-token-canary-value");
  });
});
