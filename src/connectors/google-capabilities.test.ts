import { describe, expect, it } from "vitest";
import type { GogAuthService } from "./gog-auth-catalog.js";
import { createGoogleCapabilityCatalog, resolveGoogleConnectorCapabilitySelection } from "./google-capabilities.js";

const catalog: readonly GogAuthService[] = [
  { service: "gmail", user: true, scopes: ["gmail.scope"], authorization: "default-user" },
  { service: "calendar", user: true, scopes: ["calendar.scope"], authorization: "default-user" },
  { service: "drive", user: true, scopes: ["drive.scope"], authorization: "default-user" },
  { service: "docs", user: true, scopes: ["docs.scope"], authorization: "default-user" },
  { service: "sheets", user: true, scopes: ["sheets.scope"], authorization: "default-user" },
  { service: "admin", user: false, scopes: ["admin.scope"], authorization: "workspace-service-account" },
];

describe("Google connector capability adapter", () => {
  it("labels execution support separately from authorization support", () => {
    expect(createGoogleCapabilityCatalog(catalog).map(({ capabilityId, availability }) => [capabilityId, availability])).toEqual([
      ["gmail", "executable"], ["calendar", "executable"], ["drive", "executable"], ["docs", "executable"], ["sheets", "executable"], ["admin", "authorization-only"],
    ]);
  });

  it("uses generic selection resolution while preserving Google scopes and actions", () => {
    const selection = resolveGoogleConnectorCapabilitySelection(["drive", "gmail"], catalog);
    expect(selection.services).toEqual(["gmail", "drive"]);
    expect(selection.scopes).toContain("drive.scope");
    expect(selection.allowedActions).toEqual(["gmail.messages.search", "gmail.messages.get", "gmail.messages.send", "drive.files.list"]);
    expect(() => resolveGoogleConnectorCapabilitySelection(["admin"], catalog)).toThrow("CONNECTOR_CAPABILITY_SELECTION_INVALID");
  });

  it("grants only the reviewed read actions for Drive, Docs, and Sheets", () => {
    const selection = resolveGoogleConnectorCapabilitySelection(["drive", "docs", "sheets"], catalog);
    expect(selection.allowedActions).toEqual([
      "drive.files.list",
      "docs.document.metadata",
      "sheets.spreadsheet.metadata",
    ]);
  });
});
