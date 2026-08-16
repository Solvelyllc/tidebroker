import { describe, expect, it } from "vitest";
import { GOOGLE_USER_OAUTH_SCOPES } from "./google-provisioning.js";

describe("Google user OAuth provisioning", () => {
  it("does not grant Google Cloud project administration authority", () => {
    expect(GOOGLE_USER_OAUTH_SCOPES).not.toContain("https://www.googleapis.com/auth/cloud-platform");
    expect(GOOGLE_USER_OAUTH_SCOPES).toEqual(expect.arrayContaining(["https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.send"]));
  });
});
