import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleGogCalendarListOperation } from "./google-gog.js";

describe("Google gog connector", () => {
  it("rejects legacy gog profiles that can retain ambient credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-worker-"));
    const fakeGogPath = await createFakeGog(root);
    const operation = createGoogleGogCalendarListOperation({ backend: "gog", gog: { executablePath: fakeGogPath, executableSha256: await fileSha256(fakeGogPath), configRoot: root } });
    await expect(operation.execute({ claims: {} as never, material: { kind: "gog-profile", configDirectory: root, accountAlias: "acct_opaque123" }, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { today: true, maxResults: 5 })).rejects.toThrow("GOG_CREDENTIAL_KIND_MISMATCH");
  });

  it("rejects arbitrary fields and non-opaque account selectors", async () => {
    const operation = createGoogleGogCalendarListOperation({ backend: "gog", gog: { executablePath: "/bin/false", executableSha256: await fileSha256("/bin/false"), configRoot: "/tmp" } });
    await expect(operation.execute({ claims: {} as never, material: { kind: "gog-profile", configDirectory: "/tmp", accountAlias: "person@example.com" }, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { actor: "other" } as never)).rejects.toThrow();
  });

  it("uses worker-custodied OAuth without putting credentials in URLs or output", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-oauth-worker-"));
    const fakeGogPath = await createFakeGog(root);
    const requests: { url: string; init?: RequestInit }[] = [];
    const fetcher = async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(input), init });
      return new Response(JSON.stringify({ access_token: "synthetic-access-token", token_type: "Bearer" }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const operation = createGoogleGogCalendarListOperation({ backend: "gog", gog: { executablePath: fakeGogPath, executableSha256: await fileSha256(fakeGogPath), configRoot: root, fetch: fetcher as typeof fetch } });
    const result = await operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "synthetic-refresh-token", clientId: "client-public" }, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { maxResults: 3 });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).not.toContain("synthetic-refresh-token");
    expect(String(requests[0]!.init?.body)).toContain("synthetic-refresh-token");
    const invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[]; hasToken: boolean };
    expect(invocation.hasToken).toBe(true);
    expect(invocation.argv).toEqual(["--enable-commands-exact", "calendar.events", "--readonly", "--gmail-no-send", "--no-input", "--wrap-untrusted", "--json", "--results-only", "--select", "id,summary,status,start,end,location", "calendar", "events", "--max", "3"]);
    expect(JSON.stringify(result)).not.toContain("synthetic-access-token");
  });

  it("rechecks credential generation after refresh and before invoking gog", async () => {
    const root = await mkdtemp(join(tmpdir(), "gog-revoked-refresh-")); const fakeGogPath = await createFakeGog(root);
    const operation = createGoogleGogCalendarListOperation({ backend: "gog", gog: { executablePath: fakeGogPath, executableSha256: await fileSha256(fakeGogPath), configRoot: root, fetch: (async () => new Response(JSON.stringify({ access_token: "synthetic-access-token", token_type: "Bearer" }), { status: 200 })) as typeof fetch } });
    await expect(operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "synthetic-refresh-token", clientId: "client-public" }, assertCredentialActive: async () => { throw new Error("CREDENTIAL_GENERATION_MISMATCH"); }, markProviderCallStarted: () => {} }, { maxResults: 3 })).rejects.toThrow("CREDENTIAL_GENERATION_MISMATCH");
    await expect(readFile(join(root, "fake-gog-invocation.json"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });
});
