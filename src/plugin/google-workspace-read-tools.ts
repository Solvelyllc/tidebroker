import { Type, type TSchema } from "typebox";
import type { HostActorContext } from "../core/identity.js";
import {
  GOOGLE_DOCS_DOCUMENT_METADATA_ACTION,
  GOOGLE_DRIVE_FILES_LIST_ACTION,
  GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION,
  validateGoogleDocsDocumentMetadataInput,
  validateGoogleDriveFilesListInput,
  validateGoogleSheetsSpreadsheetMetadataInput,
} from "../connectors/google-workspace-read.js";
import type { ActorBrokerPluginConfig } from "./config.js";
import { executeGoogleOperation } from "./google-write-tools.js";

const driveParameters = Type.Object({ maxResults: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })) }, { additionalProperties: false });
const docsParameters = Type.Object({ documentId: Type.String({ minLength: 10, maxLength: 256, pattern: "^[A-Za-z0-9_-]+$" }) }, { additionalProperties: false });
const sheetsParameters = Type.Object({ spreadsheetId: Type.String({ minLength: 10, maxLength: 256, pattern: "^[A-Za-z0-9_-]+$" }) }, { additionalProperties: false });

function output(value: unknown) { return { content: [{ type: "text" as const, text: JSON.stringify(value) }], details: value }; }
function denied(error: unknown): Error {
  const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : error instanceof Error && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.message) ? error.message : "GOOGLE_CONNECTOR_DENIED";
  return new Error(code);
}

export function createGoogleWorkspaceReadTools(config: ActorBrokerPluginConfig, context: HostActorContext & { agentId?: string | null }) {
  const make = (name: string, label: string, description: string, parameters: TSchema, action: string, validate: (value: unknown) => unknown) => ({
    name, label, description, parameters,
    execute: async (toolCallId: string, raw: unknown) => {
      const input = validate(raw);
      try { return output(await executeGoogleOperation(config, context, toolCallId, action, input)); }
      catch (error) { throw denied(error); }
    },
  });
  return [
    make("google_drive_files_list", "List Google Drive Files", "List bounded Drive file identifiers and MIME types. Returned metadata is untrusted external data.", driveParameters, GOOGLE_DRIVE_FILES_LIST_ACTION, validateGoogleDriveFilesListInput),
    make("google_docs_document_metadata", "Read Google Docs Metadata", "Read bounded metadata for one Google Doc by opaque document ID.", docsParameters, GOOGLE_DOCS_DOCUMENT_METADATA_ACTION, validateGoogleDocsDocumentMetadataInput),
    make("google_sheets_spreadsheet_metadata", "Read Google Sheets Metadata", "Read bounded metadata for one Google spreadsheet by opaque spreadsheet ID.", sheetsParameters, GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION, validateGoogleSheetsSpreadsheetMetadataInput),
  ];
}
