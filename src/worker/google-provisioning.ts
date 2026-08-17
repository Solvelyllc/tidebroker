import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isAbsolute } from "node:path";
import { buildAuditEvent } from "../audit/index.js";
import { GOOGLE_GOG_CONNECTOR_ID } from "../connectors/google-gog.js";
import { GOOGLE_AUTHORIZATION_ENDPOINT, GOOGLE_USERINFO_EMAIL_SCOPE, GOOGLE_USERINFO_PROFILE_SCOPE, GoogleOAuthTokenExchanger, canonicalGoogleOAuthScope } from "../connectors/google-oauth.js";
import { loadGogAuthCatalog, type GogAuthService } from "../connectors/gog-auth-catalog.js";
import { GOOGLE_CONNECTOR_BINDING_ACTIONS, resolveGoogleConnectorCapabilitySelection, type GoogleOnboardingSelection } from "../connectors/google-capabilities.js";
export type { GoogleOnboardingSelection } from "../connectors/google-capabilities.js";
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

interface GoogleConnectionRunOptions {
  readonly selection?: GoogleOnboardingSelection;
  readonly catalog?: readonly GogAuthService[];
  readonly trustedWorkerGrant?: true;
  readonly onReady?: (url: string) => void;
}

type GoogleConnectionIdentity = Pick<GoogleConnectionConfig, "subjectId" | "workspaceId"> & Partial<Pick<GoogleConnectionConfig, "workspaceMembershipsPath">>;

const GOOGLE_AUTHORIZATION_ERROR_REASONS = Object.freeze({
  access_denied: "GOOGLE_AUTH_ACCESS_DENIED",
  admin_policy_enforced: "GOOGLE_AUTH_ADMIN_POLICY_ENFORCED",
  disallowed_useragent: "GOOGLE_AUTH_DISALLOWED_USERAGENT",
  invalid_client: "GOOGLE_AUTH_INVALID_CLIENT",
  invalid_request: "GOOGLE_AUTH_INVALID_REQUEST",
  invalid_scope: "GOOGLE_AUTH_INVALID_SCOPE",
  org_internal: "GOOGLE_AUTH_ORG_INTERNAL",
  server_error: "GOOGLE_AUTH_SERVER_ERROR",
  temporarily_unavailable: "GOOGLE_AUTH_TEMPORARILY_UNAVAILABLE",
} as const);

/** Converts an untrusted provider error value into a bounded audit/page reason. */
export function classifyGoogleAuthorizationError(value: string | null): string {
  if (value === null) return "GOOGLE_AUTH_CODE_MISSING";
  return GOOGLE_AUTHORIZATION_ERROR_REASONS[value as keyof typeof GOOGLE_AUTHORIZATION_ERROR_REASONS] ?? "GOOGLE_AUTH_PROVIDER_ERROR";
}

export function isGoogleLoopbackOrigin(value: string | undefined, port: string): boolean {
  if (!/^\d{1,5}$/.test(port)) return false;
  return value === `http://127.0.0.1:${port}` || value === `http://localhost:${port}` || value === `http://[::1]:${port}`;
}

export function isGoogleLoopbackSubmission(origin: string | undefined, fetchSite: string | undefined, port: string): boolean {
  if (isGoogleLoopbackOrigin(origin, port)) return true;
  if (origin !== undefined && origin !== "null") return false;
  return fetchSite !== "cross-site";
}

/** Compatibility wrapper; provider-specific selection policy is owned by the connector adapter. */
export function resolveGoogleOnboardingSelection(values: readonly string[], catalog: readonly GogAuthService[]): GoogleOnboardingSelection {
  try { return resolveGoogleConnectorCapabilitySelection(values, catalog); }
  catch { throw new Error("GOOGLE_SERVICE_SELECTION_INVALID"); }
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
  res.setHeader("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("referrer-policy", "no-referrer"); res.setHeader("x-content-type-options", "nosniff"); res.setHeader("x-frame-options", "DENY");
}

function page(res: ServerResponse, status: number, title: string, body: string): void {
  res.statusCode = status; securityHeaders(res, "text/html; charset=utf-8");
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>:root{color-scheme:light dark}*{box-sizing:border-box}body{font:16px system-ui;max-width:48rem;margin:3rem auto;padding:1rem;line-height:1.45}h1{margin-bottom:.35rem}.sub{opacity:.75;margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));gap:.8rem;margin:1.5rem 0}.choice{display:block;border:1px solid color-mix(in srgb,currentColor 22%,transparent);border-radius:.7rem;padding:1rem;cursor:pointer}.choice:has(input:checked){border-color:#1769e0;box-shadow:0 0 0 2px #1769e033}.choice strong{display:block;margin-left:1.7rem}.choice small{display:block;opacity:.72;margin:.35rem 0 0 1.7rem}.choice input{float:left;margin:.25rem .6rem 0 0}.risk{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}.write{color:#b85c00}button,a.button{display:inline-block;border:0;padding:.75rem 1rem;background:#1769e0;color:#fff;border-radius:.45rem;text-decoration:none;font:inherit;font-weight:650;cursor:pointer}.note{padding:.8rem 1rem;border-left:3px solid #1769e0;background:#1769e014;border-radius:.2rem}</style><h1>${title}</h1>${body}`);
}

function html(value: string): string { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;"); }

function onboardingForm(csrf: string, catalog: readonly GogAuthService[], preselected?: GoogleOnboardingSelection): string {
  if (preselected) {
    return `<p class="sub">Your choices came from the actor-bound chat onboarding flow.</p><p class="note"><strong>Selected:</strong> ${preselected.services.map(html).join(", ")}</p><form method="post" action="/oauth/google/start"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Continue with Google</button></form>`;
  }
  const choices = catalog.filter((item) => item.authorization !== "workspace-service-account").map((service) => `<label class="choice"><input type="checkbox" name="service" value="${html(service.service)}"${service.authorization === "default-user" ? " checked" : ""}><strong>${html(service.service)} <span class="risk">${service.authorization === "explicit-user" ? "explicit opt-in" : "user OAuth"}</span></strong><small>${html(service.note ?? `${service.scopes.length} OAuth scope${service.scopes.length === 1 ? "" : "s"}`)}</small></label>`).join("");
  const serviceAccount = catalog.filter((item) => item.authorization === "workspace-service-account").map((item) => html(item.service)).join(", ");
  return `<p class="sub">Choose Google services before consent. The default selection is gogcli's complete user OAuth set; Photos Picker is separate.</p><form method="post" action="/oauth/google/start"><input type="hidden" name="csrf" value="${csrf}"><div class="grid">${choices}</div><p class="note"><strong>Workspace setup:</strong> ${serviceAccount} require a service account and domain-wide delegation, so they cannot be added to a user OAuth grant.</p><p class="note">Authorization and agent execution are separate: selecting a service stores its grant, but only installed Tidebroker tools can invoke it.</p><button type="submit">Continue with Google</button></form>`;
}

async function formBody(req: IncomingMessage): Promise<URLSearchParams> {
  if ((req.headers["content-type"] ?? "").split(";", 1)[0] !== "application/x-www-form-urlencoded") throw new Error("OAUTH_RESPONSE_INVALID");
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of req) { const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); bytes += data.length; if (bytes > 16 * 1024) throw new Error("OAUTH_RESPONSE_INVALID"); chunks.push(data); }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

/** One-shot, loopback-only account connection. Authorization codes arrive in a POST body. */
export async function runGoogleAccountConnection(worker: CredentialWorkerServiceConfig, connection: GoogleConnectionIdentity, options: GoogleConnectionRunOptions = {}): Promise<void> {
  if (!worker.googleOAuth || !worker.oauthStateRoot || !worker.accountBindingsPath) throw new Error("GOOGLE_OAUTH_NOT_CONFIGURED");
  let catalog = options.catalog;
  if (!catalog) {
    if (worker.googleExecution.backend !== "gog") throw new Error("GOG_AUTH_CATALOG_REQUIRED");
    const gog = worker.googleExecution;
    catalog = await loadGogAuthCatalog({ executablePath: gog.executablePath, executableSha256: gog.executableSha256, configRoot: gog.configRoot, timeoutMs: gog.timeoutMs, maxOutputBytes: gog.maxOutputBytes });
  }
  const googleOAuth = worker.googleOAuth;
  const accountBindingsPath = worker.accountBindingsPath;
  const subjectId = defineSubjectId(connection.subjectId); const workspaceId = defineWorkspaceId(connection.workspaceId);
  if (options.trustedWorkerGrant !== true && !connection.workspaceMembershipsPath) throw new Error("GOOGLE_CONNECTION_CONFIG_INVALID");
  const bound = await bindDeploymentRun({ subjectId, workspaceId, workspaces: options.trustedWorkerGrant === true ? { isMember: (candidateSubject, candidateWorkspace) => candidateSubject === subjectId && candidateWorkspace === workspaceId } : new FileWorkspaceMembershipStore(connection.workspaceMembershipsPath!) });
  if (!bound.ok) throw new Error(bound.code);
  const clientId = await readSecureTextFile(googleOAuth.clientIdFile);
  const clientSecret = googleOAuth.clientSecretFile ? await readSecureTextFile(googleOAuth.clientSecretFile) : undefined;
  const keys = new SecureFileCredentialEncryptionKeys(worker.encryption.activeKeyId, worker.encryption.keys.map((entry) => ({ id: entry.id, path: entry.keyFile })));
  const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(worker.credentialRoot, worker.metadataRoot), keys);
  const audit = new FileAuditSink(worker.auditRoot); if (!await audit.ready()) throw new Error("WORKER_AUDIT_UNAVAILABLE");
  const requestId = `req_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
  const bindingDigest = createHash("sha256").update(`${subjectId}\0${workspaceId}\0${GOOGLE_GOG_CONNECTOR_ID}`, "utf8").digest("hex");
  const custodian = new OAuthCredentialCustodian({ connectorId: GOOGLE_GOG_CONNECTOR_ID, state: new FileOAuthStateBackend(worker.oauthStateRoot), credentials,
    exchanger: new GoogleOAuthTokenExchanger({ clientId, ...(clientSecret === undefined ? {} : { clientSecret }), redirectUri: googleOAuth.redirectUri }),
    expectedIssuer: "https://accounts.google.com", expectedAudience: clientId, allowedScopes: Object.freeze([...new Set(catalog.flatMap((item) => item.authorization === "workspace-service-account" ? [] : item.scopes.map(canonicalGoogleOAuthScope)).concat("openid", GOOGLE_USERINFO_EMAIL_SCOPE, GOOGLE_USERINFO_PROFILE_SCOPE))]),
    newAccountId: () => defineAccountId(`acct_${bindingDigest.slice(0, 32)}`), newCredentialHandle: () => defineCredentialHandle(`cred_${bindingDigest.slice(32)}`) });
  const verifier = randomBytes(32).toString("base64url"); const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  const csrf = randomBytes(32).toString("base64url");
  let pending: Awaited<ReturnType<OAuthCredentialCustodian["begin"]>> | undefined;
  let selection: GoogleOnboardingSelection | undefined = options.selection;
  const redirect = new URL(googleOAuth.redirectUri); let settled = false;
  await new Promise<void>((resolve, reject) => {
    const server = createServer((req, res) => { void (async () => {
      let failureReason = "GOOGLE_CONNECTION_FAILED";
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        if (req.method === "GET" && url.pathname === "/") { page(res, 200, "Connect Google", onboardingForm(csrf, catalog, options.selection)); return; }
        if (req.method === "POST" && url.pathname === "/oauth/google/start") {
          if (pending) { page(res, 409, "Connection already started", "<p>Google authorization has already started for this session.</p>"); return; }
          const form = await formBody(req);
          if (form.get("csrf") !== csrf) { page(res, 400, "Reload Google connection", "<p>This onboarding page is stale.</p><p><a class=\"button\" href=\"/\">Reload onboarding</a></p>"); return; }
          const fetchSite = Array.isArray(req.headers["sec-fetch-site"]) ? req.headers["sec-fetch-site"][0] : req.headers["sec-fetch-site"];
          if (!isGoogleLoopbackSubmission(req.headers.origin, fetchSite, redirect.port)) { page(res, 400, "Reload Google connection", "<p>The browser submitted from a non-loopback origin.</p><p><a class=\"button\" href=\"/\">Reload onboarding</a></p>"); return; }
          if (!selection) {
            try { selection = resolveGoogleOnboardingSelection(form.getAll("service"), catalog); }
            catch { page(res, 400, "Choose Google services", `<p>Select at least one user OAuth service.</p><p><a class="button" href="/">Back to choices</a></p>`); return; }
          }
          pending = await custodian.begin({ binding: bound.binding, redirectTargetId: "google_loopback", scopes: selection.scopes, pkceChallenge: challenge });
          const authorization = new URL(GOOGLE_AUTHORIZATION_ENDPOINT);
          for (const [key, value] of Object.entries({ client_id: clientId, redirect_uri: googleOAuth.redirectUri, response_type: "code", response_mode: "form_post", scope: selection.scopes.join(" "), access_type: "offline", prompt: "consent", include_granted_scopes: "false", state: pending.stateId, nonce: pending.nonce, code_challenge: challenge, code_challenge_method: "S256" })) authorization.searchParams.set(key, value);
          res.statusCode = 303; securityHeaders(res, "text/plain; charset=utf-8"); res.setHeader("location", authorization.toString()); res.end("Continue with Google"); return;
        }
        if (req.method !== "POST" || url.pathname !== redirect.pathname) { res.statusCode = 404; securityHeaders(res, "text/plain; charset=utf-8"); res.end("Not found"); return; }
        const form = await formBody(req); const stateId = form.get("state"); const code = form.get("code");
        if (!pending || !selection || stateId !== pending.stateId) { failureReason = "GOOGLE_AUTH_STATE_INVALID"; throw new Error("OAUTH_INVALID_STATE"); }
        const providerError = form.get("error");
        if (providerError || !code) { failureReason = classifyGoogleAuthorizationError(providerError); throw new Error("OAUTH_RESPONSE_INVALID"); }
        const completed = await custodian.complete({ stateId, authorizationCode: code, pkceVerifier: verifier });
        await audit.append(buildAuditEvent({ actor: { id: subjectId, kind: "human" }, workspace: workspaceId, connector: GOOGLE_GOG_CONNECTOR_ID, action: "credential.connect", outcome: "succeeded", correlation: { requestId }, reasonCode: "CREDENTIAL_CONNECTED" }));
        await new FileAccountBindingStore(accountBindingsPath, { legacyConnectorId: GOOGLE_GOG_CONNECTOR_ID, allowedActionsByConnector: new Map([[GOOGLE_GOG_CONNECTOR_ID, new Set(GOOGLE_CONNECTOR_BINDING_ACTIONS)]]) }).upsert({ subjectId, workspaceId, connectorId: GOOGLE_GOG_CONNECTOR_ID, accountId: completed.accountId, credentialHandle: completed.credentialHandle, credentialGeneration: completed.generation, allowedActions: selection.allowedActions, enabled: true });
        page(res, 200, "Google connected", `<p>The credential is encrypted in worker custody.</p><p><strong>Authorized services:</strong> ${selection.services.map(html).join(", ")}</p><p>You can close this page.</p>`);
        settled = true; server.close(() => resolve());
      } catch (error) {
        if (failureReason === "GOOGLE_CONNECTION_FAILED" && error instanceof Error && /^(?:GOOGLE_OAUTH|OAUTH_)[A-Z0-9_]{1,80}$/.test(error.message)) failureReason = error.message;
        try { await audit.append(buildAuditEvent({ actor: { id: subjectId, kind: "human" }, workspace: workspaceId, connector: GOOGLE_GOG_CONNECTOR_ID, action: "credential.connect", outcome: "failed", correlation: { requestId }, reasonCode: failureReason })); } catch {}
        page(res, 400, "Connection denied", `<p>The connection was not accepted.</p><p class="note"><strong>Reason:</strong> ${html(failureReason)}</p><p>Close this page and start a new connection.</p>`); if (!settled) { settled = true; server.close(() => reject(new Error(failureReason))); }
      }
    })(); });
    const timeout = setTimeout(() => { if (!settled) { settled = true; server.close(() => reject(new Error("GOOGLE_CONNECTION_EXPIRED"))); } }, 10 * 60 * 1000); timeout.unref();
    server.once("close", () => clearTimeout(timeout)); server.once("error", reject);
    server.listen(Number(redirect.port), "127.0.0.1", () => {
      const url = `http://127.0.0.1:${redirect.port}/?attempt=${encodeURIComponent(requestId)}`;
      options.onReady?.(url);
      if (!options.onReady) process.stdout.write(`GOOGLE_CONNECT_READY ${url}\n`);
    });
  });
}

/** Owns at most one short-lived loopback consent session for the worker. */
export class GoogleConnectionSessionManager {
  #active: Promise<void> | null = null;
  constructor(readonly worker: CredentialWorkerServiceConfig, readonly catalog: readonly GogAuthService[]) {}

  async begin(identity: Pick<GoogleConnectionConfig, "subjectId" | "workspaceId">, selection: GoogleOnboardingSelection): Promise<Readonly<{ url: string; expiresAt: number }>> {
    if (this.#active) throw new Error("GOOGLE_CONNECTION_ALREADY_ACTIVE");
    let readyResolve!: (url: string) => void; let readyReject!: (error: Error) => void;
    const ready = new Promise<string>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const completion = runGoogleAccountConnection(this.worker, identity, { selection, catalog: this.catalog, trustedWorkerGrant: true, onReady: readyResolve });
    this.#active = completion;
    void completion.catch((error: unknown) => readyReject(error instanceof Error ? error : new Error("GOOGLE_CONNECTION_FAILED"))).finally(() => { if (this.#active === completion) this.#active = null; });
    const url = await ready;
    return Object.freeze({ url, expiresAt: Date.now() + 10 * 60 * 1000 });
  }
}
