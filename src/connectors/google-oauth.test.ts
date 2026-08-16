import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { GOOGLE_JWKS_ENDPOINT, GOOGLE_TOKEN_ENDPOINT, GoogleOAuthTokenExchanger } from "./google-oauth.js";

describe("Google OAuth exchanger", () => {
  it("validates the signed OIDC binding and keeps the code out of the token URL", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "key_1" })).toString("base64url");
    const claims = Buffer.from(JSON.stringify({ iss: "https://accounts.google.com", aud: "client-public", nonce: "non_opaque", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 })).toString("base64url");
    const signature = sign("RSA-SHA256", Buffer.from(`${header}.${claims}`, "ascii"), privateKey).toString("base64url");
    const idToken = `${header}.${claims}.${signature}`; const seen: string[] = [];
    const fetcher = async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input); seen.push(url);
      if (url === GOOGLE_TOKEN_ENDPOINT) {
        expect(url).not.toContain("authorization-code-canary"); expect(String(init?.body)).toContain("authorization-code-canary");
        return new Response(JSON.stringify({ refresh_token: "refresh-canary", id_token: idToken, scope: "openid https://www.googleapis.com/auth/calendar.readonly" }), { status: 200 });
      }
      expect(url).toBe(GOOGLE_JWKS_ENDPOINT);
      return new Response(JSON.stringify({ keys: [{ ...(publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "key_1", alg: "RS256", use: "sig" }] }), { status: 200 });
    };
    const result = await new GoogleOAuthTokenExchanger({ clientId: "client-public", redirectUri: "http://127.0.0.1:8765/oauth/google/callback", fetch: fetcher as typeof fetch }).exchange({ authorizationCode: "authorization-code-canary", pkceVerifier: "v".repeat(43), redirectTargetId: "google_loopback" });
    expect(result).toMatchObject({ issuer: "https://accounts.google.com", audience: "client-public", nonce: "non_opaque", refreshToken: "refresh-canary" });
    expect(seen).toEqual([GOOGLE_TOKEN_ENDPOINT, GOOGLE_JWKS_ENDPOINT]);
  });
});
