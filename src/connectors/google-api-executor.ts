import type { CredentialMaterial } from "../credentials/store.js";
import { googleAccessToken } from "./google-oauth.js";

export interface GoogleDirectExecutionOptions {
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

export type GoogleWorkspaceExecutionOptions =
  | { readonly backend: "direct"; readonly direct?: GoogleDirectExecutionOptions }
  | { readonly backend: "gog"; readonly gog: import("./gog-executor.js").GogExecutionOptions };

const GOOGLE_API_ORIGIN = "https://www.googleapis.com";

function oauth(material: CredentialMaterial | undefined): Extract<CredentialMaterial, { kind: "oauth2" }> {
  if (!material || material.kind !== "oauth2") throw new Error("GOOGLE_CREDENTIAL_KIND_MISMATCH");
  return material;
}

function limits(options: GoogleDirectExecutionOptions): { timeoutMs: number; maxResponseBytes: number } {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000 ||
    !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 4 * 1024 * 1024) {
    throw new Error("GOOGLE_DIRECT_LIMITS_INVALID");
  }
  return { timeoutMs, maxResponseBytes };
}

function fixedGoogleUrl(path: string, query?: URLSearchParams): URL {
  if (!path.startsWith("/") || path.includes("\0")) throw new Error("GOOGLE_DIRECT_REQUEST_INVALID");
  const url = new URL(path, GOOGLE_API_ORIGIN);
  if (url.origin !== GOOGLE_API_ORIGIN) throw new Error("GOOGLE_DIRECT_REQUEST_INVALID");
  if (query) url.search = query.toString();
  return url;
}

async function boundedText(response: Response, maxResponseBytes: number): Promise<string> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxResponseBytes) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maxResponseBytes) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  return text;
}

function validateJsonBounds(value: unknown, depth = 0, state = { nodes: 0 }): void {
  state.nodes += 1;
  if (depth > 32 || state.nodes > 20_000) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  if (typeof value === "string" && value.length > 1024 * 1024) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  if (Array.isArray(value)) for (const item of value) validateJsonBounds(item, depth + 1, state);
  else if (typeof value === "object" && value !== null) {
    for (const [key, child] of Object.entries(value)) {
      if (key.length > 1024) throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
      validateJsonBounds(child, depth + 1, state);
    }
  }
}

export async function googleApiRequest(options: GoogleDirectExecutionOptions, material: CredentialMaterial | undefined, input: {
  readonly method: "GET" | "POST" | "PATCH" | "DELETE";
  readonly path: string;
  readonly query?: URLSearchParams;
  readonly body?: unknown;
  readonly allowEmpty?: boolean;
  /** Re-check revocation after token refresh and immediately before network I/O. */
  readonly assertCredentialActive: () => Promise<void>;
  readonly markProviderCallStarted: () => void;
}): Promise<unknown> {
  const runtime = limits(options);
  const fetcher = options.fetch ?? fetch;
  const accessToken = await googleAccessToken(oauth(material), fetcher);
  await input.assertCredentialActive();
  input.markProviderCallStarted();
  const response = await fetcher(fixedGoogleUrl(input.path, input.query), {
    method: input.method,
    headers: {
      authorization: `Bearer ${accessToken}`,
      ...(input.body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    redirect: "error",
    signal: AbortSignal.timeout(runtime.timeoutMs),
  });
  if (!response.ok) throw new Error("GOOGLE_DIRECT_OPERATION_FAILED");
  const text = await boundedText(response, runtime.maxResponseBytes);
  if (text.length === 0 && input.allowEmpty === true) return null;
  try {
    const value = JSON.parse(text) as unknown;
    if (typeof value !== "object" || value === null) throw new Error();
    validateJsonBounds(value);
    return value;
  } catch {
    throw new Error("GOOGLE_DIRECT_RESPONSE_INVALID");
  }
}

export function boundedExternalText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, "").slice(0, maxLength);
}

export function externalRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}
