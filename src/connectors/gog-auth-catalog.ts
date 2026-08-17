import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, stat, type FileHandle } from "node:fs/promises";
import { isAbsolute } from "node:path";

export type GogAuthAuthorization = "default-user" | "explicit-user" | "workspace-service-account";
export interface GogAuthService {
  readonly service: string;
  readonly user: boolean;
  readonly scopes: readonly string[];
  readonly apis?: readonly string[];
  readonly note?: string;
  readonly authorization: GogAuthAuthorization;
}

const DEFAULT_USER = new Set(["gmail", "calendar", "chat", "classroom", "drive", "driveactivity", "drivelabels", "docs", "slides", "contacts", "tasks", "sheets", "people", "forms", "sites", "meet", "appscript", "analytics", "searchconsole", "ads", "youtube", "photos"]);
const EXPLICIT_USER = new Set(["photospicker"]);
const SERVICE_ACCOUNT = new Set(["admin", "groups", "keep"]);
const ALL = new Set([...DEFAULT_USER, ...EXPLICIT_USER, ...SERVICE_ACCOUNT]);

function plain(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function stringArray(value: unknown): value is string[] { return Array.isArray(value) && value.length <= 256 && value.every((item) => typeof item === "string" && item.length > 0 && item.length <= 2048); }

export function parseGogAuthCatalog(value: unknown): readonly GogAuthService[] {
  if (!plain(value) || Object.keys(value).some((key) => !["services", "externalContent"].includes(key)) || !Array.isArray(value.services) || value.services.length !== ALL.size) throw new Error("GOG_AUTH_CATALOG_INVALID");
  if (value.externalContent !== undefined && (!plain(value.externalContent) || Object.keys(value.externalContent).length !== 3 || value.externalContent.source !== "google_api" || value.externalContent.untrusted !== true || value.externalContent.wrapped !== true)) throw new Error("GOG_AUTH_CATALOG_INVALID");
  const seen = new Set<string>();
  const services = value.services.map((raw): GogAuthService => {
    if (!plain(raw) || Object.keys(raw).some((key) => !["service", "user", "scopes", "apis", "note"].includes(key)) || typeof raw.service !== "string" || !ALL.has(raw.service) || seen.has(raw.service) || typeof raw.user !== "boolean" || !stringArray(raw.scopes) || raw.apis !== undefined && !stringArray(raw.apis) || raw.note !== undefined && (typeof raw.note !== "string" || raw.note.length > 4096)) throw new Error("GOG_AUTH_CATALOG_INVALID");
    seen.add(raw.service);
    const authorization: GogAuthAuthorization = DEFAULT_USER.has(raw.service) ? "default-user" : EXPLICIT_USER.has(raw.service) ? "explicit-user" : "workspace-service-account";
    if (raw.user !== (authorization === "default-user")) throw new Error("GOG_AUTH_CATALOG_INVALID");
    return Object.freeze({ service: raw.service, user: raw.user, scopes: Object.freeze([...raw.scopes]), ...(raw.apis === undefined ? {} : { apis: Object.freeze([...raw.apis]) }), ...(raw.note === undefined ? {} : { note: raw.note }), authorization });
  });
  if (seen.size !== ALL.size || [...ALL].some((service) => !seen.has(service))) throw new Error("GOG_AUTH_CATALOG_INVALID");
  return Object.freeze(services);
}

async function openVerified(path: string, expectedSha256: string): Promise<FileHandle> {
  let handle: FileHandle | undefined;
  try {
    if (!isAbsolute(path) || !/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error();
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o100) === 0 || (info.mode & 0o022) !== 0 || typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error();
    if (createHash("sha256").update(await handle.readFile()).digest("hex") !== expectedSha256) throw new Error();
    return handle;
  } catch { await handle?.close(); throw new Error("GOG_EXECUTABLE_INVALID"); }
}

export async function loadGogAuthCatalog(options: { readonly executablePath: string; readonly executableSha256: string; readonly configRoot: string; readonly timeoutMs?: number; readonly maxOutputBytes?: number }): Promise<readonly GogAuthService[]> {
  const timeoutMs = options.timeoutMs ?? 15_000; const max = options.maxOutputBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000 || !Number.isSafeInteger(max) || max < 1024 || max > 4 * 1024 * 1024) throw new Error("GOG_AUTH_CATALOG_INVALID");
  const home = await realpath(options.configRoot); if (!(await stat(home)).isDirectory() || process.platform !== "linux") throw new Error("GOG_RUNTIME_INVALID");
  const executable = await openVerified(options.executablePath, options.executableSha256);
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn("/proc/self/fd/3", ["--enable-commands-exact", "auth.services", "--no-input", "--json", "auth", "services"], { cwd: home, env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", GOG_HOME: home }, shell: false, stdio: ["ignore", "pipe", "pipe", executable.fd], windowsHide: true, detached: true });
      const chunks: Buffer[] = []; let bytes = 0; let terminal = "GOG_AUTH_CATALOG_FAILED"; let settled = false;
      const stop = (code: string) => { terminal = code; if (child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); return; } catch {} } child.kill("SIGKILL"); };
      const timer = setTimeout(() => stop("GOG_AUTH_CATALOG_TIMEOUT"), timeoutMs); timer.unref();
      const count = (chunk: Buffer, retain: boolean) => { bytes += chunk.length; if (bytes > max) stop("GOG_AUTH_CATALOG_LIMIT"); else if (retain) chunks.push(chunk); };
      child.stdout!.on("data", (chunk: Buffer) => count(chunk, true)); child.stderr!.on("data", (chunk: Buffer) => count(chunk, false)); child.on("error", () => stop("GOG_AUTH_CATALOG_FAILED"));
      child.on("close", (code) => { clearTimeout(timer); if (settled) return; settled = true; if (code !== 0) { reject(new Error(terminal)); return; } try { resolve(parseGogAuthCatalog(JSON.parse(Buffer.concat(chunks).toString("utf8")))); } catch { reject(new Error("GOG_AUTH_CATALOG_INVALID")); } });
    });
  } finally { await executable.close(); }
}
