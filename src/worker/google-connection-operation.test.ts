import { describe, expect, it } from "vitest";
import { GOG_DEFAULT_USER_SERVICE_IDS, GOG_EXPLICIT_USER_SERVICE_IDS, GOG_WORKSPACE_SERVICE_ACCOUNT_IDS, validateGoogleConnectionBeginInput } from "./google-connection-operation.js";

describe("Google connection begin input", () => {
  it("publishes the complete gog v0.37 user authorization catalog", () => {
    expect(GOG_DEFAULT_USER_SERVICE_IDS).toHaveLength(22);
    expect(GOG_EXPLICIT_USER_SERVICE_IDS).toEqual(["photospicker"]);
    expect(GOG_WORKSPACE_SERVICE_ACCOUNT_IDS).toEqual(["admin", "groups", "keep"]);
  });

  it("accepts unique user OAuth services", () => {
    expect(validateGoogleConnectionBeginInput({ services: ["drive", "docs", "photospicker"] })).toEqual({ services: ["drive", "docs", "photospicker"] });
  });

  it("rejects service-account-only, duplicate, and unknown services", () => {
    expect(() => validateGoogleConnectionBeginInput({ services: ["admin"] })).toThrow("GOOGLE_CONNECTION_INPUT_INVALID");
    expect(() => validateGoogleConnectionBeginInput({ services: ["drive", "drive"] })).toThrow("GOOGLE_CONNECTION_INPUT_INVALID");
    expect(() => validateGoogleConnectionBeginInput({ services: ["maps"] })).toThrow("GOOGLE_CONNECTION_INPUT_INVALID");
  });
});
