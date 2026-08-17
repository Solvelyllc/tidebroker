import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFakeGog, fileSha256 } from "../../test-fixtures/fake-gog-helper.js";
import { createGoogleWorkspaceReadOperations, GOOGLE_DOCS_DOCUMENT_METADATA_ACTION, GOOGLE_DRIVE_FILES_LIST_ACTION, GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION, validateGoogleDocsDocumentMetadataInput, validateGoogleDriveFilesListInput } from "./google-workspace-read.js";

const material = { kind: "oauth2" as const, refreshToken: "refresh-token-canary", clientId: "client-id" };
const fetcher = vi.fn(async () => new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 }));

describe("Google Workspace reviewed read adapters", () => {
  it("validates bounded inputs and rejects unknown fields", () => {
    expect(validateGoogleDriveFilesListInput({ maxResults: 25 })).toEqual({ maxResults: 25 });
    expect(() => validateGoogleDriveFilesListInput({ maxResults: 101 })).toThrow("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
    expect(validateGoogleDocsDocumentMetadataInput({ documentId: "doc_123456789" })).toEqual({ documentId: "doc_123456789" });
    expect(() => validateGoogleDocsDocumentMetadataInput({ documentId: "bad/id" })).toThrow("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  });

  it("runs only the three exact read-only gog commands with strict projections", async () => {
    const root = await mkdtemp(join(tmpdir(), "google-workspace-read-"));
    const executablePath = await createFakeGog(root); const executableSha256 = await fileSha256(executablePath);
    const operations = createGoogleWorkspaceReadOperations({ backend: "gog", gog: { executablePath, executableSha256, configRoot: root, fetch: fetcher as typeof fetch } });
    const context = { claims: {} as never, material, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} };
    const drive = operations.find((item) => item.action === GOOGLE_DRIVE_FILES_LIST_ACTION)!;
    await expect(drive.execute(context, { maxResults: 5 })).resolves.toMatchObject({ source: "gog:drive", untrusted: true });
    let invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[] };
    expect(invocation.argv).toEqual(expect.arrayContaining(["--enable-commands-exact", "drive.ls", "--readonly", "--results-only", "--select", "id,mimeType", "drive", "ls"]));
    const docs = operations.find((item) => item.action === GOOGLE_DOCS_DOCUMENT_METADATA_ACTION)!;
    await expect(docs.execute(context, { documentId: "doc_123456789" })).resolves.toMatchObject({ source: "gog:docs", untrusted: true });
    invocation = JSON.parse(await readFile(join(root, "fake-gog-invocation.json"), "utf8")) as { argv: string[] };
    expect(invocation.argv).not.toContain("--results-only"); expect(invocation.argv).toContain("docs.info");
    const sheets = operations.find((item) => item.action === GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION)!;
    await expect(sheets.execute(context, { spreadsheetId: "sheet_123456789" })).resolves.toMatchObject({ source: "gog:sheets", untrusted: true });
  });
});
