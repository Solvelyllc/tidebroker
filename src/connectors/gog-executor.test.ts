import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { runGogOAuthCommand } from "./gog-executor.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-token-canary", clientId: "client-id" };
const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));
const fakeGogPath = fileURLToPath(new URL("../../test-fixtures/fake-gog.mjs", import.meta.url));

describe("gog subprocess boundary", () => {
  it("uses a closed environment, keeps tokens out of argv/output, and strips secret-shaped fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-executor-"));
    const result = await runGogOAuthCommand({ executablePath: fakeGogPath, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_123", "--sanitize-content"] }) as { argv: string[]; envKeys: string[]; hasToken: boolean; nested: { ok: boolean }; access_token?: string };
    expect(result.envKeys).toEqual(["GOG_ACCESS_TOKEN", "GOG_HOME", "LANG", "LC_ALL"]); expect(result.hasToken).toBe(true); expect(result.nested).toEqual({ ok: true });
    expect(result.argv).toEqual(expect.arrayContaining(["--no-input", "--wrap-untrusted", "--json"]));
    expect(result.access_token).toBeUndefined(); expect(result.argv.join(" ")).not.toContain("access-token-canary-value"); expect(JSON.stringify(result)).not.toContain("access-token-canary-value");
  });

  it("rejects attempts to relax the Gmail send boundary", async () => {
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", configRoot: "/tmp" }, material, { command: "gmail.send", mutating: true, argv: ["gmail", "send"] })).rejects.toThrow("GOG_COMMAND_INVALID");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", configRoot: "/tmp" }, material, { command: "gmail.get", mutating: false, allowGmailSend: true, argv: ["gmail", "get", "msg_123"] })).rejects.toThrow("GOG_COMMAND_INVALID");
  });
});
