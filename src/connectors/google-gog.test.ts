import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createGoogleGogCalendarListOperation } from "./google-gog.js";

const fakeGogPath = fileURLToPath(new URL("../../test-fixtures/fake-gog.mjs", import.meta.url));

describe("Google gog connector", () => {
  it("uses a fixed safe command surface and strips credential-shaped output", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-worker-"));
    const profile = join(root, "profile");
    await mkdir(profile);
    const operation = createGoogleGogCalendarListOperation({ executablePath: fakeGogPath, configRoot: root });
    const output = await operation.execute({ claims: {} as never, material: { kind: "gog-profile", configDirectory: profile, accountAlias: "acct_opaque123" } }, { today: true, maxResults: 5 }) as { argv: string[]; token?: string; items: unknown[] };
    expect(output.token).toBeUndefined();
    expect(output.argv).toEqual(["--account", "acct_opaque123", "--enable-commands-exact", "calendar.events", "--gmail-no-send", "--readonly", "--no-input", "--wrap-untrusted", "--json", "calendar", "events", "--today", "--max", "5"]);
    expect(output.items).toEqual([{ id: "event-1" }]);
  });

  it("rejects arbitrary fields and non-opaque account selectors", async () => {
    const operation = createGoogleGogCalendarListOperation({ executablePath: "/bin/false", configRoot: "/tmp" });
    await expect(operation.execute({ claims: {} as never, material: { kind: "gog-profile", configDirectory: "/tmp", accountAlias: "person@example.com" } }, { actor: "other" } as never)).rejects.toThrow();
  });

  it("uses worker-custodied OAuth without putting credentials in URLs or output", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-oauth-worker-"));
    const requests: { url: string; init?: RequestInit }[] = [];
    const fetcher = async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(input), init });
      return new Response(JSON.stringify({ access_token: "synthetic-access-token", token_type: "Bearer" }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const operation = createGoogleGogCalendarListOperation({ executablePath: fakeGogPath, configRoot: root, fetch: fetcher as typeof fetch });
    const result = await operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "synthetic-refresh-token", clientId: "client-public" } }, { maxResults: 3 }) as { argv: string[]; hasAccessToken: boolean; access_token?: string };
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).not.toContain("synthetic-refresh-token");
    expect(String(requests[0]!.init?.body)).toContain("synthetic-refresh-token");
    expect(result.hasAccessToken).toBe(true);
    expect(result.access_token).toBeUndefined();
    expect(result.argv).toEqual(["--enable-commands-exact", "calendar.events", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "calendar", "events", "--max", "3"]);
    expect(JSON.stringify(result)).not.toContain("synthetic-access-token");
  });
});
