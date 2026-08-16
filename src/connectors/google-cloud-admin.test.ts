import { describe, expect, it, vi } from "vitest";
import { createGoogleProjectAdminOperations, GOOGLE_PROJECT_SERVICES_ENABLE_ACTION, validateGoogleProjectServicesEnableInput } from "./google-cloud-admin.js";

describe("Google project administration connector", () => {
  it("enables only the exact validated services in the deployment-owned project", async () => {
    expect(() => validateGoogleProjectServicesEnableInput({ services: ["calendar-json.googleapis.com"], projectId: "attacker-project" })).toThrow("GOOGLE_PROJECT_ADMIN_INPUT_INVALID");
    const fetcher = vi.fn(async (url: URL | string | Request, init?: RequestInit) => {
      const target = String(url);
      if (target.includes("oauth2.googleapis.com/token")) return new Response(JSON.stringify({ access_token: "access-token-canary-value", token_type: "Bearer" }), { status: 200 });
      expect(target).toContain("/projects/deployment-project/services/calendar-json.googleapis.com:enable");
      expect(init?.method).toBe("POST");
      expect(String((init?.headers as Record<string, string>).authorization)).toContain("access-token-canary-value");
      return new Response(JSON.stringify({ name: "operations/service-enable-1" }), { status: 200 });
    });
    const operation = createGoogleProjectAdminOperations("deployment-project", { fetch: fetcher as typeof fetch }).find((item) => item.action === GOOGLE_PROJECT_SERVICES_ENABLE_ACTION)!;
    await expect(operation.execute({ claims: {} as never, material: { kind: "oauth2", refreshToken: "refresh-canary", clientId: "client-id" }, assertCredentialActive: async () => {}, markProviderCallStarted: () => {} }, { services: ["calendar-json.googleapis.com"] })).resolves.toEqual({ enabled: ["calendar-json.googleapis.com"] });
  });
});
