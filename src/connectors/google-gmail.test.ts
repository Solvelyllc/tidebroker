import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleGmailOperations, GOOGLE_GMAIL_MESSAGE_GET_ACTION, GOOGLE_GMAIL_MESSAGE_SEND_ACTION, GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION, validateGoogleGmailMessageSendInput } from "./google-gmail.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-canary", clientId: "client-id" };
const token = () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 });

async function fakeGog() {
  const root = await mkdtemp(join(tmpdir(), "gmail-gog-"));
  const executablePath = await createFakeGog(root);
  const fetcher = vi.fn(async () => token());
  return { root, options: { backend: "gog" as const, gog: { executablePath, executableSha256: await fileSha256(executablePath), configRoot: root, fetch: fetcher as typeof fetch } }, fetcher };
}

describe("Google Gmail gog connector", () => {
  it("searches through the exact read-only gog command and marks output untrusted", async () => {
    const { root, options, fetcher } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { query: "is:unread", maxResults: 5 }) as { source: string; untrusted: boolean; result: unknown };
    expect(output).toMatchObject({ source: "gog:gmail", untrusted: true });
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; hasToken: boolean };
    expect(invocation.argv).toEqual(["--enable-commands-exact", "gmail.messages.search", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "--results-only", "--select", "id,threadId,date,internalDateIso,from,subject,labels", "gmail", "messages", "search", "is:unread", "--max", "5"]);
    expect(invocation.hasToken).toBe(true); expect(fetcher).toHaveBeenCalledOnce();
    expect(JSON.stringify(output)).not.toContain("access-token-canary-value");
  });

  it("reads through gog's sanitized-content mode", async () => {
    const { root, options } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGE_GET_ACTION)!;
    await operation.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { messageId: "msg_456" });
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[] };
    expect(invocation.argv).toEqual(["--enable-commands-exact", "gmail.get", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "--results-only", "--select", "id,threadId,labelIds,snippet,internalDate,sizeEstimate,headers,body", "gmail", "get", "msg_456", "--sanitize-content"]);
  });

  it("sends only through the exact approved gog command and keeps the body out of argv", async () => {
    expect(() => validateGoogleGmailMessageSendInput({ to: ["victim@example.com\r\nBcc: attacker@example.com"], subject: "x", textBody: "y" })).toThrow("GOOGLE_GMAIL_INPUT_INVALID");
    const { root, options } = await fakeGog();
    const operation = createGoogleGmailOperations(options).find((item) => item.action === GOOGLE_GMAIL_MESSAGE_SEND_ACTION)!;
    const output = await operation.execute({ claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { to: ["recipient@example.com"], subject: "Approved message", textBody: "Exact body" }) as { sent: boolean };
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; bodyLength: number; bodyDigest: string };
    expect(output.sent).toBe(true); expect(invocation.bodyLength).toBe(10); expect(invocation.bodyDigest).toBe(createHash("sha256").update("Exact body").digest("hex"));
    expect(invocation.argv).toEqual(["--enable-commands-exact", "gmail.send", "--no-input", "--wrap-untrusted", "--json", "--results-only", "--select", "messageId,threadId", "gmail", "send", "--to", "recipient@example.com", "--subject", "Approved message", "--body-file", "-"]);
    expect(invocation.argv.join(" ")).not.toContain("Exact body"); expect(invocation.argv.join(" ")).not.toContain("access-token-canary-value");
  });
});
