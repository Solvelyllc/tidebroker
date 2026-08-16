import { describe, expect, it, vi } from "vitest";
import { createGoogleGogCalendarListOperation } from "./google-gog.js";
import { createGoogleCalendarWriteOperations, GOOGLE_CALENDAR_EVENT_CREATE_ACTION, GOOGLE_CALENDAR_EVENT_DELETE_ACTION } from "./google-calendar-write.js";
import { createGoogleGmailOperations, GOOGLE_GMAIL_MESSAGE_GET_ACTION, GOOGLE_GMAIL_MESSAGE_SEND_ACTION, GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION } from "./google-gmail.js";
import { googleApiRequest } from "./google-api-executor.js";

const ACCESS = "access-token-canary-value";
const REFRESH = "refresh-token-canary-value";
const material = { kind: "oauth2" as const, refreshToken: REFRESH, clientId: "public-client-id" };
const tokenResponse = () => new Response(JSON.stringify({ access_token: ACCESS, token_type: "Bearer" }), { status: 200, headers: { "content-type": "application/json" } });

function sequential(...responses: Response[]) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    const response = responses.shift(); if (!response) throw new Error("unexpected request");
    return response;
  });
  return { calls, fetcher: fetcher as unknown as typeof fetch };
}

describe("direct Google execution", () => {
  it("lists Calendar events at the fixed endpoint without exposing credentials", async () => {
    const { calls, fetcher } = sequential(tokenResponse(), new Response(JSON.stringify({ items: [{ id: "event_1", summary: "External title", access_token: ACCESS }] }), { status: 200 }));
    const operation = createGoogleGogCalendarListOperation({ backend: "direct", direct: { fetch: fetcher } });
    const output = await operation.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { maxResults: 2 });
    expect(calls[1]!.url).toBe("https://www.googleapis.com/calendar/v3/calendars/primary/events?singleEvents=true&orderBy=startTime&maxResults=2");
    expect(calls[1]!.init?.method).toBe("GET");
    expect(new Headers(calls[1]!.init?.headers).get("authorization")).toBe(`Bearer ${ACCESS}`);
    expect(JSON.stringify(output)).not.toContain(ACCESS); expect(calls[1]!.url).not.toContain(ACCESS); expect(calls[1]!.url).not.toContain(REFRESH);
  });

  it("creates and deletes Calendar events with exact fixed paths and bodies", async () => {
    const { calls, fetcher } = sequential(tokenResponse(), new Response(JSON.stringify({ id: "event_12345", status: "confirmed" }), { status: 200 }), tokenResponse(), new Response(null, { status: 204 }));
    const operations = createGoogleCalendarWriteOperations({ backend: "direct", direct: { fetch: fetcher } });
    const create = operations.find((item) => item.action === GOOGLE_CALENDAR_EVENT_CREATE_ACTION)!;
    const remove = operations.find((item) => item.action === GOOGLE_CALENDAR_EVENT_DELETE_ACTION)!;
    await create.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { summary: "Approved", start: "2026-08-16T12:00:00Z", end: "2026-08-16T12:30:00Z", attendees: ["person@example.test"] });
    await remove.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { eventId: "event_12345" });
    expect(calls[1]!.url).toBe("https://www.googleapis.com/calendar/v3/calendars/primary/events?sendUpdates=all");
    expect(calls[1]!.init?.method).toBe("POST");
    expect(JSON.parse(String(calls[1]!.init?.body))).toEqual({ summary: "Approved", start: { dateTime: "2026-08-16T12:00:00Z" }, end: { dateTime: "2026-08-16T12:30:00Z" }, attendees: [{ email: "person@example.test" }] });
    expect(calls[3]!.url).toBe("https://www.googleapis.com/calendar/v3/calendars/primary/events/event_12345?sendUpdates=all");
    expect(calls[3]!.init?.method).toBe("DELETE");
  });

  it("searches and reads Gmail through strict bounded projections", async () => {
    const plain = Buffer.from("safe plain body", "utf8").toString("base64url");
    const html = Buffer.from("<script>unsafe()</script>", "utf8").toString("base64url");
    const metadata = { id: "msg_1", threadId: "thread_1", snippet: "preview", payload: { headers: [{ name: "From", value: "Sender <sender@example.test>" }, { name: "Subject", value: "Hello" }, { name: "X-Secret", value: ACCESS }] } };
    const full = { ...metadata, payload: { ...metadata.payload, parts: [{ mimeType: "text/plain", body: { data: plain } }, { mimeType: "text/html", body: { data: html } }, { mimeType: "application/octet-stream", filename: "secret.bin", body: { attachmentId: "attachment" } }] } };
    const { calls, fetcher } = sequential(tokenResponse(), new Response(JSON.stringify({ messages: [{ id: "msg_1" }] }), { status: 200 }), tokenResponse(), new Response(JSON.stringify(metadata), { status: 200 }), tokenResponse(), new Response(JSON.stringify(full), { status: 200 }));
    const operations = createGoogleGmailOperations({ backend: "direct", direct: { fetch: fetcher } });
    const search = operations.find((item) => item.action === GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION)!;
    const get = operations.find((item) => item.action === GOOGLE_GMAIL_MESSAGE_GET_ACTION)!;
    const found = await search.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { query: "is:unread", maxResults: 1 });
    const read = await get.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { messageId: "msg_1" });
    expect(calls[1]!.url).toBe("https://www.googleapis.com/gmail/v1/users/me/messages?q=is%3Aunread&maxResults=1");
    expect(calls[3]!.url).toContain("/gmail/v1/users/me/messages/msg_1?format=metadata");
    expect(calls[5]!.url).toBe("https://www.googleapis.com/gmail/v1/users/me/messages/msg_1?format=full");
    expect(JSON.stringify(found)).not.toContain("X-Secret");
    expect(JSON.stringify(read)).toContain("safe plain body");
    expect(JSON.stringify(read)).not.toContain("unsafe"); expect(JSON.stringify(read)).not.toContain("attachment"); expect(JSON.stringify(read)).not.toContain(ACCESS);
  });

  it("sends Gmail as plain-text MIME without returning the request content", async () => {
    const { calls, fetcher } = sequential(tokenResponse(), new Response(JSON.stringify({ id: "sent_1", threadId: "thread_1" }), { status: 200 }));
    const operation = createGoogleGmailOperations({ backend: "direct", direct: { fetch: fetcher } }).find((item) => item.action === GOOGLE_GMAIL_MESSAGE_SEND_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { to: ["recipient@example.test"], subject: "Approved subject", textBody: "Approved body" });
    expect(calls[1]!.url).toBe("https://www.googleapis.com/gmail/v1/users/me/messages/send"); expect(calls[1]!.init?.method).toBe("POST");
    const raw = Buffer.from(JSON.parse(String(calls[1]!.init?.body)).raw, "base64url").toString("utf8");
    expect(raw).toContain("Content-Type: text/plain"); expect(Buffer.from(raw.split("\r\n\r\n")[1]!, "base64").toString("utf8")).toBe("Approved body");
    expect(JSON.stringify(output)).not.toContain("Approved body"); expect(JSON.stringify(output)).not.toContain(ACCESS);
  });

  it("fails closed on malformed, oversized, and non-success provider responses", async () => {
    for (const response of [new Response("not-json", { status: 200 }), new Response(JSON.stringify({ error: "denied" }), { status: 403 }), new Response(JSON.stringify({ value: "x".repeat(2048) }), { status: 200 })]) {
      const { fetcher } = sequential(tokenResponse(), response);
      await expect(googleApiRequest({ fetch: fetcher, maxResponseBytes: 1024 }, material, { method: "GET", path: "/calendar/v3/calendars/primary/events", assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow(/^GOOGLE_DIRECT_/u);
    }
  });

  it("rechecks credential generation after refresh and before direct provider I/O", async () => {
    const { calls, fetcher } = sequential(tokenResponse());
    await expect(googleApiRequest({ fetch: fetcher }, material, {
      method: "GET",
      path: "/calendar/v3/calendars/primary/events",
      assertCredentialActive: async () => { throw new Error("CREDENTIAL_GENERATION_MISMATCH"); },
      markProviderCallStarted: () => {},
    })).rejects.toThrow("CREDENTIAL_GENERATION_MISMATCH");
    expect(calls).toHaveLength(1);
  });
});
