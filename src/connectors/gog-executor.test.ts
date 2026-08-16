import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { runGogOAuthCommand } from "./gog-executor.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-token-canary", clientId: "client-id" };
const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));

describe("gog subprocess boundary", () => {
  it("uses a closed environment, keeps tokens out of argv/output, and strips secret-shaped fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-executor-")); const executablePath = join(root, "gog-safe");
    await writeFile(executablePath, "#!/usr/bin/node\nprocess.stdout.write(JSON.stringify({argv:process.argv.slice(2),envKeys:Object.keys(process.env).sort(),hasToken:Boolean(process.env.GOG_ACCESS_TOKEN),access_token:process.env.GOG_ACCESS_TOKEN,nested:{client_secret:'strip-me',ok:true}}))\n", { mode: 0o700 });
    const result = await runGogOAuthCommand({ executablePath, configRoot: root, fetch: fetcher as typeof fetch }, material, { command: "gmail.get", mutating: false, argv: ["gmail", "get", "msg_123", "--sanitize-content"] }) as { argv: string[]; envKeys: string[]; hasToken: boolean; nested: { ok: boolean }; access_token?: string };
    expect(result.envKeys).toEqual(["GOG_ACCESS_TOKEN", "GOG_HOME", "LANG", "LC_ALL"]); expect(result.hasToken).toBe(true); expect(result.nested).toEqual({ ok: true });
    expect(result.argv).toEqual(expect.arrayContaining(["--no-input", "--wrap-untrusted", "--json"]));
    expect(result.access_token).toBeUndefined(); expect(result.argv.join(" ")).not.toContain("access-token-canary-value"); expect(JSON.stringify(result)).not.toContain("access-token-canary-value");
  });

  it("rejects attempts to relax the Gmail send boundary", async () => {
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", configRoot: "/tmp" }, material, { command: "gmail.send", mutating: true, argv: ["gmail", "send"] })).rejects.toThrow("GOG_COMMAND_INVALID");
    await expect(runGogOAuthCommand({ executablePath: "/bin/false", configRoot: "/tmp" }, material, { command: "gmail.get", mutating: false, allowGmailSend: true, argv: ["gmail", "get", "msg_123"] })).rejects.toThrow("GOG_COMMAND_INVALID");
  });
});
