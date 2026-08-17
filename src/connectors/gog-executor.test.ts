import { mkdtemp, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { parseGogOutput, runGogOAuthCommand, validateGogExecutionOptions } from "./gog-executor.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-token-canary", clientId: "client-id" };
const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));

describe("gog subprocess boundary", () => {
  it("uses a closed environment and returns only the command-specific schema", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-executor-"));
    const executablePath = await createFakeGog(root);
    const executableSha256 = await fileSha256(executablePath);
    const result = await runGogOAuthCommand({ executablePath, executableSha256, configRoot: root, httpsProxy: "http://127.0.0.1:3128", fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_123", "--sanitize-content"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} });
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; envKeys: string[]; hasToken: boolean };
    expect(invocation.envKeys).toEqual(["GOG_ACCESS_TOKEN", "GOG_HOME", "HTTPS_PROXY", "LANG", "LC_ALL", "NO_PROXY"]); expect(invocation.hasToken).toBe(true);
    expect(invocation.argv).toEqual(expect.arrayContaining(["--no-input", "--wrap-untrusted", "--json", "--results-only", "--select"]));
    expect(JSON.stringify(result)).not.toContain("access-token-canary-value");
  });

  it("rejects unknown fields, access-token values, and a changed executable hash", async () => {
    expect(() => parseGogOutput("gmail.get", { id: "msg_1", arbitrary: "access-token-canary-value" }, "access-token-canary-value")).toThrow("GOG_OUTPUT_INVALID");
    const root = await mkdtemp(join(tmpdir(), "gog-hash-")); const executablePath = await createFakeGog(root); const executableSha256 = await fileSha256(executablePath);
    await writeFile(executablePath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await expect(runGogOAuthCommand({ executablePath, executableSha256, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_1"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_EXECUTABLE_INVALID");
  });

  it("canonicalizes legacy sanitized Gmail envelopes and strips attachments", () => {
    expect(parseGogOutput("gmail.get", {
      message: {
        id: "msg_1", threadId: "thread_1", labelIds: ["INBOX"], snippet: "bounded",
        internalDate: 1, sizeEstimate: 2, headers: { from: "sender@example.com", subject: "Subject" },
        body: "sanitized body", attachments: [{ filename: "not-returned.txt", attachmentId: "not-returned" }],
      },
      headers: { from: "sender@example.com" }, body: "sanitized body",
    })).toEqual({
      id: "msg_1", threadId: "thread_1", labelIds: ["INBOX"], snippet: "bounded",
      internalDate: 1, sizeEstimate: 2, headers: { from: "sender@example.com", subject: "Subject" }, body: "sanitized body",
    });
  });

  it("accepts only gog's exact untrusted-content marker on projected records", () => {
    const marker = { untrusted: true, source: "google_api", wrapped: true };
    expect(parseGogOutput("calendar.events", [{ id: "evt_1", summary: "wrapped", externalContent: marker }])).toEqual([{ id: "evt_1", summary: "wrapped", externalContent: marker }]);
    expect(parseGogOutput("gmail.messages.search", [{ id: "msg_1", subject: "wrapped", externalContent: marker }])).toEqual([{ id: "msg_1", subject: "wrapped", externalContent: marker }]);
    expect(() => parseGogOutput("calendar.events", [{ id: "evt_1", externalContent: { ...marker, source: "other" } }])).toThrow("GOG_OUTPUT_INVALID");
  });

  it("enforces exact Drive, Docs, and Sheets metadata projections", () => {
    expect(parseGogOutput("drive.ls", [{ id: "file_123", mimeType: "application/pdf" }])).toEqual([{ id: "file_123", mimeType: "application/pdf" }]);
    expect(parseGogOutput("docs.info", { "file.id": "doc_123", "file.mimeType": "application/vnd.google-apps.document", "document.documentId": "doc_123" })).toEqual({ "file.id": "doc_123", "file.mimeType": "application/vnd.google-apps.document", "document.documentId": "doc_123" });
    expect(parseGogOutput("sheets.metadata", { spreadsheetId: "sheet_123" })).toEqual({ spreadsheetId: "sheet_123" });
    expect(() => parseGogOutput("drive.ls", [{ id: "file_123", mimeType: "application/pdf", name: "not projected" }])).toThrow("GOG_OUTPUT_INVALID");
    expect(() => parseGogOutput("docs.info", { "file.id": false, "file.mimeType": "x", "document.documentId": "doc_123" })).toThrow("GOG_OUTPUT_INVALID");
    expect(() => parseGogOutput("sheets.metadata", { spreadsheetId: "sheet_123", title: "not projected" })).toThrow("GOG_OUTPUT_INVALID");
  });

  it.runIf(process.platform === "linux")("executes the verified inode even if its configured path is replaced", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-inode-")); const executablePath = await createFakeGog(root); const executableSha256 = await fileSha256(executablePath);
    const originalPath = join(root, "verified-gog");
    const result = await runGogOAuthCommand({ executablePath, executableSha256, configRoot: root, fetch: fetcher as typeof fetch }, material, {
      command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_1"],
      assertCredentialActive: async () => {
        await rename(executablePath, originalPath);
        await writeFile(executablePath, "#!/bin/sh\nexit 99\n", { mode: 0o700 });
      },
      markProviderCallStarted: () => {},
    });
    expect(result).toMatchObject({ id: "msg_456" });
  });

  it("rejects a symlinked executable even when its target hash matches", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-symlink-")); const target = await createFakeGog(root); const executableSha256 = await fileSha256(target); const link = join(root, "gog-link");
    await symlink(target, link);
    await expect(runGogOAuthCommand({ executablePath: link, executableSha256, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_1"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_EXECUTABLE_INVALID");
  });

  it("rejects attempts to relax the Gmail send boundary", async () => {
    const executableSha256 = await fileSha256("/bin/false");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", executableSha256, configRoot: "/tmp" }, material, { command: "gmail.send", mutating: true, argv: ["gmail", "send"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_COMMAND_INVALID");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", executableSha256, configRoot: "/tmp" }, material, { command: "gmail.get", mutating: false, allowGmailSend: true, argv: ["gmail", "get", "msg_123"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_COMMAND_INVALID");
  });

  it("accepts only credential-free loopback HTTPS proxy URLs", () => {
    const base = { executablePath: "/bin/false", executableSha256: "a".repeat(64), configRoot: "/tmp" };
    expect(validateGogExecutionOptions({ ...base, httpsProxy: "http://127.0.0.1:3128" }).httpsProxy).toBe("http://127.0.0.1:3128");
    for (const httpsProxy of ["https://127.0.0.1:3128", "http://localhost:3128", "http://10.0.0.1:3128", "http://user:pass@127.0.0.1:3128", "http://127.0.0.1:3128/path"]) expect(() => validateGogExecutionOptions({ ...base, httpsProxy })).toThrow("loopback URL");
  });
});
