import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { parseGogOutput, runGogOAuthCommand } from "./gog-executor.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-token-canary", clientId: "client-id" };
const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));

describe("gog subprocess boundary", () => {
  it("uses a closed environment and returns only the command-specific schema", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-executor-"));
    const executablePath = await createFakeGog(root);
    const executableSha256 = await fileSha256(executablePath);
    const result = await runGogOAuthCommand({ executablePath, executableSha256, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_123", "--sanitize-content"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} });
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; envKeys: string[]; hasToken: boolean };
    expect(invocation.envKeys).toEqual(["GOG_ACCESS_TOKEN", "GOG_HOME", "LANG", "LC_ALL"]); expect(invocation.hasToken).toBe(true);
    expect(invocation.argv).toEqual(expect.arrayContaining(["--no-input", "--wrap-untrusted", "--json", "--results-only", "--select"]));
    expect(JSON.stringify(result)).not.toContain("access-token-canary-value");
  });

  it("rejects unknown fields, access-token values, and a changed executable hash", async () => {
    expect(() => parseGogOutput("gmail.get", { id: "msg_1", arbitrary: "access-token-canary-value" }, "access-token-canary-value")).toThrow("GOG_OUTPUT_INVALID");
    const root = await mkdtemp(join(tmpdir(), "gog-hash-")); const executablePath = await createFakeGog(root); const executableSha256 = await fileSha256(executablePath);
    await writeFile(executablePath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await expect(runGogOAuthCommand({ executablePath, executableSha256, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_1"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_EXECUTABLE_INVALID");
  });

  it("rejects attempts to relax the Gmail send boundary", async () => {
    const executableSha256 = await fileSha256("/bin/false");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", executableSha256, configRoot: "/tmp" }, material, { command: "gmail.send", mutating: true, argv: ["gmail", "send"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_COMMAND_INVALID");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", executableSha256, configRoot: "/tmp" }, material, { command: "gmail.get", mutating: false, allowGmailSend: true, argv: ["gmail", "get", "msg_123"], assertCredentialActive: async () => {}, markProviderCallStarted: () => {} })).rejects.toThrow("GOG_COMMAND_INVALID");
  });
});
