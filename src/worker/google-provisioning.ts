import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isAbsolute } from "node:path";
import { buildAuditEvent } from "../audit/index.js";
import { GOOGLE_AUTHORIZATION_ENDPOINT, GOOGLE_CALENDAR_EVENTS_SCOPE, GOOGLE_CALENDAR_LIST_READONLY_SCOPE, GOOGLE_CALENDARS_READONLY_SCOPE, GOOGLE_CLOUD_PLATFORM_SCOPE, GOOGLE_GMAIL_READONLY_SCOPE, GOOGLE_GMAIL_SEND_SCOPE, GoogleOAuthTokenExchanger } from "../connectors/google-oauth.js";
import { GOOGLE_CALENDAR_ALLOWED_ACTIONS } from "../durable/accounts.js";
import { defineAccountId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { bindDeploymentRun } from "../core/run-binding.js";
import { defineSubjectId } from "../core/subject.js";
import { OAuthCredentialCustodian } from "../credentials/oauth.js";
import { EncryptedCredentialStore } from "../credentials/store.js";
import { FileAccountBindingStore } from "../durable/accounts.js";
import { FileAuditSink } from "../durable/audit.js";
import { FileCredentialRecordBackend } from "../durable/credentials.js";
import { readJsonFile } from "../durable/files.js";
import { FileWorkspaceMembershipStore } from "../durable/identity.js";
import { FileOAuthStateBackend } from "../durable/oauth.js";
import type { CredentialWorkerServiceConfig } from "./bootstrap.js";
import { readSecureTextFile, SecureFileCredentialEncryptionKeys } from "./secure-key-files.js";

export interface GoogleConnectionConfig {
  readonly version: 1;
  readonly subjectId: string;
  readonly workspaceId: string;
  readonly workspaceMembershipsPath: string;
}

export async function loadGoogleConnectionConfig(path: string): Promise<GoogleConnectionConfig> {
  if (!isAbsolute(path)) throw new Error("GOOGLE_CONNECTION_CONFIG_INVALID");
  const value = await readJsonFile(path, 16 * 1024);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("GOOGLE_CONNECTION_CONFIG_INVALID");
  const record = value as Record<string, unknown>; const allowed = new Set(["version", "subjectId", "workspaceId", "workspaceMembershipsPath"]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || record.version !== 1 || typeof record.subjectId !== "string" || typeof record.workspaceId !== "string" ||
    typeof record.workspaceMembershipsPath !== "string" || !isAbsolute(record.workspaceMembershipsPath)) throw new Error("GOOGLE_CONNECTION_CONFIG_INVALID");
  defineSubjectId(record.subjectId); defineWorkspaceId(record.workspaceId);
  return record as unknown as GoogleConnectionConfig;
}

function securityHeaders(res: ServerResponse, contentType: string): void {
  res.setHeader("cache-control", "no-store, max-age=0"); res.setHeader("content-type", contentType);
  res.setHeader("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("referrer-policy", "no-referrer"); res.setHeader("x-content-type-options", "nosniff"); res.setHeader("x-frame-options", "DENY");
}

function page(res: ServerResponse, status: number, title: string, body: string): void {
  res.statusCode = status; securityHeaders(res, "text/html; charset=utf-8");
  res.end(`<!doctype html><meta charset="utf-8"><title>${title}</title><style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:1rem}a{display:inline-block;padding:.7rem 1rem;background:#1769e0;color:#fff;border-radius:.4rem;text-decoration:none}</style><h1>${title}</h1>${body}`);
}

async function formBody(req: IncomingMessage): Promise<URLSearchParams> {
  if ((req.headers["content-type"] ?? "").split(";", 1)[0] !== "application/x-www-form-urlencoded") throw new Error("OAUTH_RESPONSE_INVALID");
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of req) { const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); bytes += data.length; if (bytes > 16 * 1024) throw new Error("OAUTH_RESPONSE_INVALID"); chunks.push(data); }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

/** One-shot, loopback-only account connection. Authorization codes arrive in a POST body. */
export async function runGoogleAccountConnection(worker: CredentialWorkerServiceConfig, connection: GoogleConnectionConfig): Promise<void> {
  if (!worker.googleOAuth || !worker.oauthStateRoot || !worker.accountBindingsPath) throw new Error("GOOGLE_OAUTH_NOT_CONFIGURED");
  const accountBindingsPath = worker.accountBindingsPath;
  const subjectId = defineSubjectId(connection.subjectId); const workspaceId = defineWorkspaceId(connection.workspaceId);
  const memberships = new FileWorkspaceMembershipStore(connection.workspaceMembershipsPath);
  const bound = await bindDeploymentRun({ subjectId, workspaceId, workspaces: memberships });
  if (!bound.ok) throw new Error(bound.code);
  const clientId = await readSecureTextFile(worker.googleOAuth.clientIdFile);
  const clientSecret = worker.googleOAuth.clientSecretFile ? await readSecureTextFile(worker.googleOAuth.clientSecretFile) : undefined;
  const keys = new SecureFileCredentialEncryptionKeys(worker.encryption.activeKeyId, worker.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(worker.credentialRoot, worker.metadataRoot), keys);
  const audit = new FileAuditSink(worker.auditRoot); if (!await audit.ready()) throw new Error("WORKER_AUDIT_UNAVAILABLE");
  const requestId = `req_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
  const bindingDigest = createHash("sha256").update(`${subjectId}\0${workspaceId}\0google-calendar`, "utf8").digest("hex");
  const custodian = new OAuthCredentialCustodian({ connectorId: "google-gog" as never, state: new FileOAuthStateBackend(worker.oauthStateRoot), credentials,
    exchanger: new GoogleOAuthTokenExchanger({ clientId, ...(clientSecret === undefined ? {} : { clientSecret }), redirectUri: worker.googleOAuth.redirectUri }),
    expectedIssuer: "https://accounts.google.com", expectedAudience: clientId, allowedScopes: ["openid", GOOGLE_CALENDAR_EVENTS_SCOPE, GOOGLE_CALENDAR_LIST_READONLY_SCOPE, GOOGLE_CALENDARS_READONLY_SCOPE, GOOGLE_CLOUD_PLATFORM_SCOPE, GOOGLE_GMAIL_READONLY_SCOPE, GOOGLE_GMAIL_SEND_SCOPE],
    newAccountId: () => defineAccountId(`acct_${bindingDigest.slice(0, 32)}`), newCredentialHandle: () => defineCredentialHandle(`cred_${bindingDigest.slice(32)}`) });
  const verifier = randomBytes(32).toString("base64url"); const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  const requestedScopes = ["openid", GOOGLE_CALENDAR_EVENTS_SCOPE, GOOGLE_CALENDAR_LIST_READONLY_SCOPE, GOOGLE_CALENDARS_READONLY_SCOPE, GOOGLE_CLOUD_PLATFORM_SCOPE, GOOGLE_GMAIL_READONLY_SCOPE, GOOGLE_GMAIL_SEND_SCOPE] as const;
  const pending = await custodian.begin({ binding: bound.binding, redirectTargetId: "google_loopback", scopes: requestedScopes, pkceChallenge: challenge });
  const authorization = new URL(GOOGLE_AUTHORIZATION_ENDPOINT);
  for (const [key, value] of Object.entries({ client_id: clientId, redirect_uri: worker.googleOAuth.redirectUri, response_type: "code", response_mode: "form_post", scope: requestedScopes.join(" "), access_type: "offline", prompt: "consent", include_granted_scopes: "false", state: pending.stateId, nonce: pending.nonce, code_challenge: challenge, code_challenge_method: "S256" })) authorization.searchParams.set(key, value);
  const redirect = new URL(worker.googleOAuth.redirectUri); let settled = false;
  await new Promise<void>((resolve, reject) => {
    const server = createServer((req, res) => { void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        if (req.method === "GET" && url.pathname === "/") { page(res, 200, "Connect Google", `<p>This grants Calendar access, Gmail read/send access, and project API administration for the existing deployment project. Every email send, Calendar write, or project change still requires a separate explicit approval.</p><p><a href="${authorization.toString().replaceAll("&", "&amp;")}">Continue with Google</a></p>`); return; }
        if (req.method !== "POST" || url.pathname !== redirect.pathname) { res.statusCode = 404; securityHeaders(res, "text/plain; charset=utf-8"); res.end("Not found"); return; }
        const form = await formBody(req); const stateId = form.get("state"); const code = form.get("code");
        if (stateId !== pending.stateId || !code || form.get("error")) throw new Error("OAUTH_INVALID_STATE");
        const completed = await custodian.complete({ stateId, authorizationCode: code, pkceVerifier: verifier });
        await audit.append(buildAuditEvent({ actor: { id: subjectId, kind: "human" }, workspace: workspaceId, connector: "google-gog", action: "credential.connect", outcome: "succeeded", correlation: { requestId }, reasonCode: "CREDENTIAL_CONNECTED" }));
        await new FileAccountBindingStore(accountBindingsPath).upsert({ subjectId, workspaceId, accountId: completed.accountId, credentialHandle: completed.credentialHandle, credentialGeneration: completed.generation, allowedActions: [...GOOGLE_CALENDAR_ALLOWED_ACTIONS], enabled: true });
        page(res, 200, "Google connected", "<p>Calendar and Gmail credentials are encrypted in worker custody. You can close this page.</p>");
        settled = true; server.close(() => resolve());
      } catch {
        try { await audit.append(buildAuditEvent({ actor: { id: subjectId, kind: "human" }, workspace: workspaceId, connector: "google-gog", action: "credential.connect", outcome: "failed", correlation: { requestId }, reasonCode: "GOOGLE_CONNECTION_FAILED" })); } catch {}
        page(res, 400, "Connection denied", "<p>The connection was not accepted. Close this page and start a new connection.</p>"); if (!settled) { settled = true; server.close(() => reject(new Error("GOOGLE_CONNECTION_FAILED"))); }
      }
    })(); });
    const timeout = setTimeout(() => { if (!settled) { settled = true; server.close(() => reject(new Error("GOOGLE_CONNECTION_EXPIRED"))); } }, 10 * 60 * 1000); timeout.unref();
    server.once("close", () => clearTimeout(timeout)); server.once("error", reject);
    server.listen(Number(redirect.port), "127.0.0.1", () => process.stdout.write(`GOOGLE_CONNECT_READY http://127.0.0.1:${redirect.port}/\n`));
  });
}
