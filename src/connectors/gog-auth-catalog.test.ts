import { describe, expect, it } from "vitest";
import { GOG_DEFAULT_USER_SERVICE_IDS, GOG_EXPLICIT_USER_SERVICE_IDS, GOG_WORKSPACE_SERVICE_ACCOUNT_IDS } from "../worker/google-connection-operation.js";
import { parseGogAuthCatalog } from "./gog-auth-catalog.js";

function payload() {
  return { services: [
    ...GOG_DEFAULT_USER_SERVICE_IDS.map((service) => ({ service, user: true, scopes: [`scope:${service}`], apis: [`${service}.googleapis.com`] })),
    ...GOG_WORKSPACE_SERVICE_ACCOUNT_IDS.map((service) => ({ service, user: false, scopes: [`scope:${service}`] })),
    ...GOG_EXPLICIT_USER_SERVICE_IDS.map((service) => ({ service, user: false, scopes: [`scope:${service}`], note: "Explicit opt-in" })),
  ] };
}

describe("gog auth service catalog", () => {
  it("classifies all 26 pinned v0.37 services", () => {
    const catalog = parseGogAuthCatalog({ ...payload(), externalContent: { source: "google_api", untrusted: true, wrapped: true } });
    expect(catalog).toHaveLength(26);
    expect(catalog.filter((item) => item.authorization === "default-user")).toHaveLength(22);
    expect(catalog.find((item) => item.service === "photospicker")?.authorization).toBe("explicit-user");
    expect(catalog.filter((item) => item.authorization === "workspace-service-account").map((item) => item.service)).toEqual(["admin", "groups", "keep"]);
  });

  it("rejects schema drift and incorrect user classification", () => {
    const extra = payload(); (extra.services[0] as Record<string, unknown>).unexpected = true;
    expect(() => parseGogAuthCatalog(extra)).toThrow("GOG_AUTH_CATALOG_INVALID");
    const wrong = payload(); wrong.services[0]!.user = false;
    expect(() => parseGogAuthCatalog(wrong)).toThrow("GOG_AUTH_CATALOG_INVALID");
  });
});
