import { resolveConnectorCapabilitySelection, validateConnectorCapabilityDescriptor, type ConnectorCapabilityAction, type ConnectorCapabilityDescriptor } from "../core/capabilities.js";
import { GOOGLE_CALENDAR_EVENT_CREATE_ACTION, GOOGLE_CALENDAR_EVENT_DELETE_ACTION, GOOGLE_CALENDAR_EVENT_UPDATE_ACTION } from "./google-calendar-write.js";
import { GOOGLE_GMAIL_MESSAGE_GET_ACTION, GOOGLE_GMAIL_MESSAGE_SEND_ACTION, GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION } from "./google-gmail.js";
import { GOOGLE_CALENDAR_EVENTS_LIST_ACTION, GOOGLE_GOG_CONNECTOR_ID } from "./google-gog.js";
import { type GogAuthService } from "./gog-auth-catalog.js";
import { GOOGLE_USERINFO_EMAIL_SCOPE, GOOGLE_USERINFO_PROFILE_SCOPE, canonicalGoogleOAuthScope } from "./google-oauth.js";
import { GOOGLE_PROJECT_SERVICES_ENABLE_ACTION } from "./google-cloud-admin.js";
import { GOOGLE_DOCS_DOCUMENT_METADATA_ACTION, GOOGLE_DRIVE_FILES_LIST_ACTION, GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION } from "./google-workspace-read.js";

export const GOG_DEFAULT_USER_SERVICE_IDS = Object.freeze([
  "gmail", "calendar", "chat", "classroom", "drive", "driveactivity", "drivelabels", "docs", "slides", "contacts", "tasks", "sheets", "people", "forms", "sites", "meet", "appscript", "analytics", "searchconsole", "ads", "youtube", "photos",
] as const);
export const GOG_EXPLICIT_USER_SERVICE_IDS = Object.freeze(["photospicker"] as const);
export const GOG_WORKSPACE_SERVICE_ACCOUNT_IDS = Object.freeze(["admin", "groups", "keep"] as const);
export const GOG_USER_OAUTH_SERVICE_IDS = Object.freeze([...GOG_DEFAULT_USER_SERVICE_IDS, ...GOG_EXPLICIT_USER_SERVICE_IDS] as const);
export type GogUserOAuthServiceId = (typeof GOG_USER_OAUTH_SERVICE_IDS)[number];

const read = (action: string): ConnectorCapabilityAction => Object.freeze({ action, mutating: false, projection: "strict", policy: "read" });
const write = (action: string): ConnectorCapabilityAction => Object.freeze({ action, mutating: true, projection: "strict", policy: "approval-required" });

const GOOGLE_EXECUTABLE_ACTIONS: Readonly<Record<string, readonly ConnectorCapabilityAction[]>> = Object.freeze({
  calendar: Object.freeze([read(GOOGLE_CALENDAR_EVENTS_LIST_ACTION), write(GOOGLE_CALENDAR_EVENT_CREATE_ACTION), write(GOOGLE_CALENDAR_EVENT_UPDATE_ACTION), write(GOOGLE_CALENDAR_EVENT_DELETE_ACTION)]),
  gmail: Object.freeze([read(GOOGLE_GMAIL_MESSAGES_SEARCH_ACTION), read(GOOGLE_GMAIL_MESSAGE_GET_ACTION), write(GOOGLE_GMAIL_MESSAGE_SEND_ACTION)]),
  drive: Object.freeze([read(GOOGLE_DRIVE_FILES_LIST_ACTION)]),
  docs: Object.freeze([read(GOOGLE_DOCS_DOCUMENT_METADATA_ACTION)]),
  sheets: Object.freeze([read(GOOGLE_SHEETS_SPREADSHEET_METADATA_ACTION)]),
});

export interface GoogleOnboardingSelection {
  readonly services: readonly string[];
  readonly scopes: readonly string[];
  readonly allowedActions: readonly string[];
}

/** Adapts the external gog catalog to Tidebroker's provider-neutral capability contract. */
export function createGoogleCapabilityCatalog(catalog: readonly GogAuthService[]): readonly ConnectorCapabilityDescriptor[] {
  return Object.freeze(catalog.map((service) => {
    const actions = GOOGLE_EXECUTABLE_ACTIONS[service.service] ?? Object.freeze([]);
    return validateConnectorCapabilityDescriptor({
      connectorId: GOOGLE_GOG_CONNECTOR_ID,
      capabilityId: service.service,
      authorization: service.authorization === "workspace-service-account" ? "service-account" : service.authorization === "explicit-user" ? "explicit-user-oauth" : "user-oauth",
      permissions: service.scopes,
      availability: actions.length === 0 ? "authorization-only" : "executable",
      actions,
      ...(service.note === undefined ? {} : { note: service.note }),
    });
  }));
}

export function resolveGoogleConnectorCapabilitySelection(values: readonly string[], catalog: readonly GogAuthService[]): GoogleOnboardingSelection {
  const selection = resolveConnectorCapabilitySelection({
    connectorId: GOOGLE_GOG_CONNECTOR_ID,
    selectedCapabilityIds: values,
    catalog: createGoogleCapabilityCatalog(catalog),
    acceptedAuthorizationKinds: ["user-oauth", "explicit-user-oauth"],
    baselinePermissions: ["openid", GOOGLE_USERINFO_EMAIL_SCOPE, GOOGLE_USERINFO_PROFILE_SCOPE],
    canonicalizePermission: canonicalGoogleOAuthScope,
  });
  return Object.freeze({ services: selection.capabilityIds, scopes: selection.permissions, allowedActions: selection.allowedActions });
}

export const GOOGLE_CONNECTOR_ALLOWED_ACTIONS = Object.freeze([...new Set(Object.values(GOOGLE_EXECUTABLE_ACTIONS).flat().map((item) => item.action))]);
/** Closed binding validation set; not every registered action is granted by user OAuth. */
export const GOOGLE_CONNECTOR_BINDING_ACTIONS = Object.freeze([...GOOGLE_CONNECTOR_ALLOWED_ACTIONS, GOOGLE_PROJECT_SERVICES_ENABLE_ACTION]);
