import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleGmailOperations, GOOGLE_GMAIL_MESSAGE_GET_ACTION, GOOGLE_GMAIL_MESSAGE_SEND_ACTION, GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION, validateGoogleGmailMessageSendInput } from "./google-gmail.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-canary", clientId: "client-id" };
const token = () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 });

async function fakeGog() {
  const root = await mkdtemp(join(tmpdir(), "gmail-gog-"));
  const executablePath = await createFakeGog(root);
  const fetcher = vi.fn(async () => token());
  return { options: { executablePath, configRoot: root, fetch: fetcher as typeof fetch }, fetcher };
}

describe("Google Gmail gog connector", () => {
  it("searches through the exact read-only gog command and marks output untrusted", async () => {
    const { options, fetcher } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material }, { query: "is:unread", maxResults: 5 }) as { source: string; untrusted: boolean; result: { argv: string[]; hasAccessToken: boolean; refresh_token?: string } };
    expect(output).toMatchObject({ source: "gog:gmail", untrusted: true });
    expect(output.result.argv).toEqual(["--enable-commands-exact", "gmail.messages.search", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "gmail", "messages", "search", "is:unread", "--max", "5"]);
    expect(output.result.hasAccessToken).toBe(true); expect(output.result.refresh_token).toBeUndefined(); expect(fetcher).toHaveBeenCalledOnce();
    expect(JSON.stringify(output)).not.toContain("access-token-canary-value");
  });

  it("reads through gog's sanitized-content mode", async () => {
    const { options } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGE_GET_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material }, { messageId: "msg_456" }) as { result: { argv: string[] } };
    expect(output.result.argv).toEqual(["--enable-commands-exact", "gmail.get", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "gmail", "get", "msg_456", "--sanitize-content"]);
  });

  it("sends only through the exact approved gog command and keeps the body out of argv", async () => {
    expect(() => validateGoogleGmailMessageSendInput({ to: ["victim@example.com\r\nBcc: attacker@example.com"], subject: "x", textBody: "y" })).toThrow("GOOGLE_GMAIL_INPUT_INVALID");
    const { options } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGE_SEND_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material }, { to: ["recipient@example.com"], subject: "Approved message", textBody: "Exact body" }) as { sent: boolean; result: { argv: string[]; bodyLength: number; bodyDigest: string } };
    expect(output.sent).toBe(true); expect(output.result.bodyLength).toBe(10); expect(output.result.bodyDigest).toBe(createHash("sha256").update("Exact body").digest("hex"));
    expect(output.result.argv).toEqual(["--enable-commands-exact", "gmail.send", "--no-input", "--wrap-untrusted", "--json", "gmail", "send", "--to", "recipient@example.com", "--subject", "Approved message", "--body-file", "-"]);
    expect(output.result.argv.join(" ")).not.toContain("Exact body"); expect(output.result.argv.join(" ")).not.toContain("access-token-canary-value");
  });
});
