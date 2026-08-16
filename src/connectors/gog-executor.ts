import { spawn } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { CredentialMaterial } from "../credentials/store.js";
import { googleAccessToken } from "./google-oauth.js";

export const GOG_COMMANDS = [
  "calendar.events",
  "calendar.create",
  "calendar.update",
  "calendar.delete",
  "gmail.messages.search",
  "gmail.get",
  "gmail.send",
] as const;
export type GogCommand = (typeof GOG_COMMANDS)[number];

export interface GogExecutionOptions {
  readonly executablePath: string;
  readonly configRoot: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly fetch?: typeof fetch;
}

const SECRET_FIELD = /(?:^|_)(?:access_?token|api_?key|authorization|client_?secret|credentials?|password|private_?key|refresh_?token|secret|token)(?:$|_)/i;

export function sanitizeGogOutput(value: unknown, depth = 0): unknown {
  if (depth > 20) throw new Error("GOG_OUTPUT_INVALID");
  if (Array.isArray(value)) return value.map((item) => sanitizeGogOutput(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) if (!SECRET_FIELD.test(key)) output[key] = sanitizeGogOutput(child, depth + 1);
    return output;
  }
  return value;
}

export function validateGogExecutionOptions(options: GogExecutionOptions): Readonly<Required<Omit<GogExecutionOptions, "fetch">> & Pick<GogExecutionOptions, "fetch">> {
  if (!isAbsolute(options.executablePath) || !isAbsolute(options.configRoot)) throw new TypeError("gog paths must be absolute.");
  const timeoutMs = options.timeoutMs ?? 30_000; const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000 || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1024 || maxOutputBytes > 4 * 1024 * 1024) throw new TypeError("gog limits are invalid.");
  return Object.freeze({ ...options, timeoutMs, maxOutputBytes });
}

/**
 * Executes one baked/allowlisted gog command. The worker supplies a freshly
 * minted access token only in the child's closed environment: never argv,
 * persistent gog state, logs, audit events, or provider URLs.
 */
export async function runGogOAuthCommand(options: GogExecutionOptions, material: Extract<CredentialMaterial, { kind: "oauth2" }>, input: {
  readonly command: GogCommand;
  readonly argv: readonly string[];
  readonly mutating: boolean;
  readonly allowGmailSend?: boolean;
  readonly stdin?: string;
}): Promise<unknown> {
  const runtime = validateGogExecutionOptions(options);
  if (!GOG_COMMANDS.includes(input.command) || input.argv.some((part) => typeof part !== "string" || part.includes("\0"))) throw new Error("GOG_COMMAND_INVALID");
  if (input.command === "gmail.send" && input.allowGmailSend !== true || input.command !== "gmail.send" && input.allowGmailSend === true) throw new Error("GOG_COMMAND_INVALID");
  const [home, executable] = await Promise.all([realpath(runtime.configRoot), realpath(runtime.executablePath)]);
  const [homeStat, executableStat] = await Promise.all([stat(home), stat(executable)]);
  if (!homeStat.isDirectory() || !executableStat.isFile()) throw new Error("GOG_RUNTIME_INVALID");
  const accessToken = await googleAccessToken(material, runtime.fetch ?? fetch);
  const argv = [
    "--enable-commands-exact", input.command,
    ...(input.mutating ? [] : ["--readonly"]),
    ...(input.allowGmailSend === true ? [] : ["--gmail-no-send"]),
    "--no-input", "--wrap-untrusted", "--json",
    ...input.argv,
  ];
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, argv, {
      cwd: home,
      env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", GOG_HOME: home, GOG_ACCESS_TOKEN: accessToken },
      shell: false,
      stdio: [input.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      windowsHide: true,
      detached: process.platform !== "win32",
    });
    const chunks: Buffer[] = []; let bytes = 0; let terminal = "GOG_EXECUTION_FAILED"; let settled = false;
    const stop = (code: string) => {
      terminal = code;
      if (process.platform !== "win32" && child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); return; } catch {} }
      child.kill("SIGKILL");
    };
    const timer = setTimeout(() => stop("GOG_TIMEOUT"), runtime.timeoutMs); timer.unref();
    const count = (chunk: Buffer, retain: boolean) => { bytes += chunk.length; if (bytes > runtime.maxOutputBytes) stop("GOG_OUTPUT_LIMIT"); else if (retain) chunks.push(chunk); };
    child.stdout!.on("data", (chunk: Buffer) => count(chunk, true));
    child.stderr!.on("data", (chunk: Buffer) => count(chunk, false));
    child.on("error", () => stop("GOG_EXECUTION_FAILED"));
    child.on("close", (exitCode) => {
      clearTimeout(timer); if (settled) return; settled = true;
      if (exitCode !== 0) { reject(new Error(terminal)); return; }
      try { resolve(sanitizeGogOutput(JSON.parse(Buffer.concat(chunks).toString("utf8")))); }
      catch { reject(new Error("GOG_OUTPUT_INVALID")); }
    });
    if (input.stdin !== undefined && child.stdin) { child.stdin.on("error", () => stop("GOG_EXECUTION_FAILED")); child.stdin.end(input.stdin, "utf8"); }
  });
}
