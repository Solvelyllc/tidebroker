import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleCalendarWriteOperations, GOOGLE_CALENDAR_EVENT_CREATE_ACTION, validateGoogleCalendarEventUpdateInput } from "./google-calendar-write.js";

describe("Google Calendar gog write connector", () => {
  it("validates updates and invokes the exact baked gog create command", async () => {
    expect(() => validateGoogleCalendarEventUpdateInput({ eventId: "event_12345" })).toThrow("GOOGLE_CALENDAR_INPUT_INVALID");
    const root = await mkdtemp(join(tmpdir(), "calendar-gog-"));
    const executablePath = await createFakeGog(root);
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));
    const operation = createGoogleCalendarWriteOperations({ backend: "gog", gog: { executablePath, executableSha256: await fileSha256(executablePath), configRoot: root, fetch: fetcher as typeof fetch } }).find((item) => item.action === GOOGLE_CALENDAR_EVENT_CREATE_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "refresh-canary", clientId: "client-id" }, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { summary: "Approved event", start: "2026-08-15T15:00:00Z", end: "2026-08-15T15:30:00Z" });
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; hasToken: boolean };
    expect(invocation.argv).toEqual(["--enable-commands-exact", "calendar.create", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "--results-only", "--select", "id,summary,status,start,end,location", "calendar", "create", "primary", "--summary", "Approved event", "--from", "2026-08-15T15:00:00Z", "--to", "2026-08-15T15:30:00Z", "--send-updates", "all"]);
    expect(invocation.hasToken).toBe(true); expect(JSON.stringify(output)).not.toContain("access-token-canary-value");
  });
});
