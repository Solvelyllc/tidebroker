import { createPublicKey, verify as verifySignature } from "node:crypto";
import type { JsonWebKey as NodeJsonWebKey } from "node:crypto";
import type { OAuthTokenExchanger, OAuthTokenExchangeResult } from "../credentials/oauth.js";
import type { CredentialMaterial } from "../credentials/store.js";

export const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
export const GOOGLE_JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs";
export const GOOGLE_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke";
export const GOOGLE_CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";
export const GOOGLE_CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events";
export const GOOGLE_CALENDAR_LIST_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.calendarlist.readonly";
export const GOOGLE_CALENDARS_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.calendars.readonly";
export const GOOGLE_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
export const GOOGLE_GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
export const GOOGLE_GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send";

type Fetch = typeof fetch;

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  return value as Record<string, unknown>;
}

async function boundedJson(response: Response, maxBytes: number): Promise<Record<string, unknown>> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (contentLength > maxBytes) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  try { return object(JSON.parse(text) as unknown); } catch { throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID"); }
}

function decodeJwtPart(value: string): Record<string, unknown> {
  try { return object(JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown); }
  catch { throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID"); }
}

async function validateGoogleIdToken(idToken: string, audience: string, fetcher: Fetch): Promise<{ issuer: string; audience: string; nonce: string }> {
  const parts = idToken.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  const header = decodeJwtPart(parts[0]!); const claims = decodeJwtPart(parts[1]!);
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  const jwksResponse = await fetcher(GOOGLE_JWKS_ENDPOINT, { method: "GET", redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!jwksResponse.ok) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  const jwks = await boundedJson(jwksResponse, 128 * 1024);
  if (!Array.isArray(jwks.keys)) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  const jwk = jwks.keys.find((candidate) => typeof candidate === "object" && candidate !== null && (candidate as Record<string, unknown>).kid === header.kid);
  if (!jwk) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  let valid = false;
  try { valid = verifySignature("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"), createPublicKey({ key: jwk as NodeJsonWebKey, format: "jwk" }), Buffer.from(parts[2]!, "base64url")); } catch {}
  const now = Math.floor(Date.now() / 1000);
  const tokenAudience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!valid || claims.iss !== "https://accounts.google.com" && claims.iss !== "accounts.google.com" || !tokenAudience.includes(audience) ||
    tokenAudience.length > 1 && claims.azp !== audience || claims.azp !== undefined && claims.azp !== audience ||
    typeof claims.nonce !== "string" || typeof claims.exp !== "number" || claims.exp <= now ||
    typeof claims.iat !== "number" || claims.iat > now + 60) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
  return { issuer: "https://accounts.google.com", audience, nonce: claims.nonce };
}

export class GoogleOAuthTokenExchanger implements OAuthTokenExchanger {
  constructor(readonly options: { clientId: string; clientSecret?: string; redirectUri: string; fetch?: Fetch }) {}

  async exchange(input: { authorizationCode: string; pkceVerifier: string; redirectTargetId: string }): Promise<OAuthTokenExchangeResult> {
    if (input.redirectTargetId !== "google_loopback") throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
    const body = new URLSearchParams({ code: input.authorizationCode, client_id: this.options.clientId, code_verifier: input.pkceVerifier, grant_type: "authorization_code", redirect_uri: this.options.redirectUri });
    if (this.options.clientSecret !== undefined) body.set("client_secret", this.options.clientSecret);
    const response = await (this.options.fetch ?? fetch)(GOOGLE_TOKEN_ENDPOINT, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, redirect: "error", signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
    const result = await boundedJson(response, 64 * 1024);
    if (typeof result.refresh_token !== "string" || typeof result.id_token !== "string" || typeof result.scope !== "string") throw new Error("GOOGLE_OAUTH_RESPONSE_INVALID");
    const identity = await validateGoogleIdToken(result.id_token, this.options.clientId, this.options.fetch ?? fetch);
    return Object.freeze({ ...identity, grantedScopes: Object.freeze(result.scope.split(/\s+/u).filter(Boolean)), refreshToken: result.refresh_token, clientId: this.options.clientId, ...(this.options.clientSecret === undefined ? {} : { clientSecret: this.options.clientSecret }) });
  }
}

export async function googleAccessToken(material: Extract<CredentialMaterial, { kind: "oauth2" }>, fetcher: Fetch = fetch): Promise<string> {
  const body = new URLSearchParams({ client_id: material.clientId, refresh_token: material.refreshToken, grant_type: "refresh_token" });
  if (material.clientSecret !== undefined) body.set("client_secret", material.clientSecret);
  const response = await fetcher(GOOGLE_TOKEN_ENDPOINT, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, redirect: "error", signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error("GOOGLE_TOKEN_REFRESH_FAILED");
  const result = await boundedJson(response, 64 * 1024);
  if (typeof result.access_token !== "string" || result.access_token.length < 16 || result.token_type !== "Bearer") throw new Error("GOOGLE_TOKEN_REFRESH_FAILED");
  return result.access_token;
}

export async function revokeGoogleCredential(material: Extract<CredentialMaterial, { kind: "oauth2" }>, fetcher: Fetch = fetch): Promise<void> {
  const response = await fetcher(GOOGLE_REVOCATION_ENDPOINT, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: material.refreshToken }), redirect: "error", signal: AbortSignal.timeout(15_000) });
  if (!response.ok && response.status !== 400) throw new Error("GOOGLE_REVOCATION_FAILED");
}
