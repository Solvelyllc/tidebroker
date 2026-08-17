import { describe, expect, it } from "vitest";
import type { GogAuthService } from "../connectors/gog-auth-catalog.js";
import { classifyGoogleAuthorizationError, isGoogleLoopbackOrigin, isGoogleLoopbackSubmission, resolveGoogleOnboardingSelection } from "./google-provisioning.js";

const catalog: readonly GogAuthService[] = [
  { service: "calendar", user: true, scopes: ["calendar.scope"], authorization: "default-user" },
  { service: "gmail", user: true, scopes: ["gmail.scope"], authorization: "default-user" },
  { service: "drive", user: true, scopes: ["drive.scope"], authorization: "default-user" },
  { service: "photospicker", user: false, scopes: ["photos.picker.scope"], authorization: "explicit-user" },
  { service: "admin", user: false, scopes: ["admin.scope"], authorization: "workspace-service-account" },
];

describe("Google gog service provisioning", () => {
  it("bounds provider authorization failures without retaining descriptions", () => {
    expect(classifyGoogleAuthorizationError("access_denied")).toBe("GOOGLE_AUTH_ACCESS_DENIED");
    expect(classifyGoogleAuthorizationError("invalid_scope")).toBe("GOOGLE_AUTH_INVALID_SCOPE");
    expect(classifyGoogleAuthorizationError("unexpected-provider-text")).toBe("GOOGLE_AUTH_PROVIDER_ERROR");
    expect(classifyGoogleAuthorizationError(null)).toBe("GOOGLE_AUTH_CODE_MISSING");
  });

  it("accepts only canonical loopback origins on the configured port", () => {
    expect(isGoogleLoopbackOrigin("http://127.0.0.1:8765", "8765")).toBe(true);
    expect(isGoogleLoopbackOrigin("http://localhost:8765", "8765")).toBe(true);
    expect(isGoogleLoopbackOrigin("http://[::1]:8765", "8765")).toBe(true);
    expect(isGoogleLoopbackOrigin("https://solver.solvely.net", "8765")).toBe(false);
    expect(isGoogleLoopbackOrigin("http://127.0.0.1:9999", "8765")).toBe(false);
    expect(isGoogleLoopbackSubmission(undefined, "same-origin", "8765")).toBe(true);
    expect(isGoogleLoopbackSubmission("null", "none", "8765")).toBe(true);
    expect(isGoogleLoopbackSubmission("null", "cross-site", "8765")).toBe(false);
    expect(isGoogleLoopbackSubmission("https://attacker.example", "same-origin", "8765")).toBe(false);
  });

  it("maps selected services to their installed catalog scopes", () => {
    const selection = resolveGoogleOnboardingSelection(["drive", "photospicker"], catalog);
    expect(selection.services).toEqual(["drive", "photospicker"]);
    expect(selection.scopes).toEqual([
      "openid",
      "https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/userinfo.profile",
      "drive.scope",
      "photos.picker.scope",
    ]);
    expect(selection.allowedActions).toEqual(["drive.files.list"]);
  });

  it("keeps OAuth authorization separate from reviewed execution actions", () => {
    const selection = resolveGoogleOnboardingSelection(["calendar", "gmail"], catalog);
    expect(selection.allowedActions).toEqual([
      "calendar.events.list", "calendar.events.create", "calendar.events.update", "calendar.events.delete",
      "gmail.messages.search", "gmail.messages.get", "gmail.messages.send",
    ]);
  });

  it("rejects empty, duplicate, unknown, and service-account selections", () => {
    expect(() => resolveGoogleOnboardingSelection([], catalog)).toThrow("GOOGLE_SERVICE_SELECTION_INVALID");
    expect(() => resolveGoogleOnboardingSelection(["drive", "drive"], catalog)).toThrow("GOOGLE_SERVICE_SELECTION_INVALID");
    expect(() => resolveGoogleOnboardingSelection(["maps"], catalog)).toThrow("GOOGLE_SERVICE_SELECTION_INVALID");
    expect(() => resolveGoogleOnboardingSelection(["admin"], catalog)).toThrow("GOOGLE_SERVICE_SELECTION_INVALID");
  });
});
