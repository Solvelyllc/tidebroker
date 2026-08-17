import type { CredentialMaterial } from "../credentials/store.js";
import type { WorkerOperation } from "../worker/worker.js";
import { runGogOAuthCommand } from "./gog-executor.js";
import type { GoogleWorkspaceExecutionOptions } from "./google-api-executor.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";

export const GOOGLE_DRIVE_FILES_LIST_ACTION = "drive.files.list" as const;
export const GOOGLE_DOCS_DOCUMENT_METADATA_ACTION = "docs.document.metadata" as const;
export const GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION = "sheets.spreadsheet.metadata" as const;

const RESOURCE_ID = /^[A-Za-z0-9_-]{10,256}$/;

function plain(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function resourceId(value: unknown): string {
  if (typeof value !== "string" || !RESOURCE_ID.test(value)) throw new Error("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  return value;
}

export function validateGoogleDriveFilesListInput(value: unknown): Readonly<{ maxResults?: number }> {
  if (!plain(value) || Object.keys(value).some((key) => key !== "maxResults")) throw new Error("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  if (value.maxResults !== undefined && (!Number.isSafeInteger(value.maxResults) || (value.maxResults as number) < 1 || (value.maxResults as number) > 100)) throw new Error("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  return Object.freeze(value.maxResults === undefined ? {} : { maxResults: value.maxResults as number });
}

export function validateGoogleDocsDocumentMetadataInput(value: unknown): Readonly<{ documentId: string }> {
  if (!plain(value) || Object.keys(value).length !== 1) throw new Error("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  return Object.freeze({ documentId: resourceId(value.documentId) });
}

export function validateGoogleSheetsSpreadsheetMetadataInput(value: unknown): Readonly<{ spreadsheetId: string }> {
  if (!plain(value) || Object.keys(value).length !== 1) throw new Error("GOOGLE_WORKSPACE_READ_INPUT_INVALID");
  return Object.freeze({ spreadsheetId: resourceId(value.spreadsheetId) });
}

function oauth(material: CredentialMaterial | undefined): Extract<CredentialMaterial, { kind: "oauth2" }> {
  if (!material || material.kind !== "oauth2") throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH");
  return material;
}

export function createGoogleWorkspaceReadOperations(options: GoogleWorkspaceExecutionOptions): readonly WorkerOperation[] {
  if (options.backend !== "gog") return Object.freeze([]);
  const execute = async (material: CredentialMaterial | undefined, input: Parameters<typeof runGogOAuthCommand>[2]) =>
    await runGogOAuthCommand(options.gog, oauth(material), input);
  return Object.freeze([
    {
      connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_DRIVE_FILES_LIST_ACTION, mutating: false,
      async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) {
        const input = validateGoogleDriveFilesListInput(raw);
        const result = await execute(material, { command: "drive.ls", mutating: false, argv: ["drive", "ls", "--all", "--max", String(input.maxResults ?? 25), "--fields", "files(id,mimeType),nextPageToken"], assertCredentialActive, markProviderCallStarted });
        return Object.freeze({ source: "gog:drive", untrusted: true, result });
      },
    },
    {
      connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_DOCS_DOCUMENT_METADATA_ACTION, mutating: false,
      async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) {
        const input = validateGoogleDocsDocumentMetadataInput(raw);
        const result = await execute(material, { command: "docs.info", mutating: false, argv: ["docs", "info", input.documentId], assertCredentialActive, markProviderCallStarted });
        return Object.freeze({ source: "gog:docs", untrusted: true, result });
      },
    },
    {
      connectorId: GOOGLE_GOG_CONNECTOR_ID, action: GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION, mutating: false,
      async execute({ material, assertCredentialActive, markProviderCallStarted }, raw) {
        const input = validateGoogleSheetsSpreadsheetMetadataInput(raw);
        const result = await execute(material, { command: "sheets.metadata", mutating: false, argv: ["sheets", "metadata", input.spreadsheetId], assertCredentialActive, markProviderCallStarted });
        return Object.freeze({ source: "gog:sheets", untrusted: true, result });
      },
    },
  ]);
}
