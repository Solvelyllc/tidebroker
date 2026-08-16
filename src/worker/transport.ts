import { createConnection, createServer, type Server, type Socket } from "node:net";
import { chmod, chown, lstat, mkdir, realpath, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import type { ConnectorId } from "../core/policy.js";
import type { CredentialGrant } from "./grant.js";
import { CredentialWorkerError, type IsolatedCredentialWorker } from "./worker.js";
import { ensurePrivateDirectory, withFileLock } from "../durable/files.js";

export interface WorkerTransportExecuteRequest {
  readonly version: 1;
  readonly type: "execute";
  readonly id: string;
  readonly connectorId: ConnectorId;
  readonly action: string;
  readonly grant: CredentialGrant;
  readonly input: unknown;
}

type WorkerTransportResponse =
  | { readonly version: 1; readonly id: string; readonly ok: true; readonly result: unknown }
  | { readonly version: 1; readonly id: string; readonly ok: false; readonly code: string };

const REQUEST_KEYS = new Set(["version", "type", "id", "connectorId", "action", "grant", "input"]);
const RESPONSE_KEYS = new Set(["version", "id", "ok", "result", "code"]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_ACTION = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,15}$/;

function encodeFrame(value: unknown, maxBytes: number): Buffer {
  let payload: Buffer;
  try { payload = Buffer.from(JSON.stringify(value), "utf8"); }
  catch { throw new Error("WORKER_PROTOCOL_ENCODING_FAILED"); }
  if (payload.length === 0 || payload.length > maxBytes) throw new Error("WORKER_PROTOCOL_FRAME_LIMIT");
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function validateRequest(value: unknown): WorkerTransportExecuteRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("WORKER_PROTOCOL_INVALID");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !REQUEST_KEYS.has(key)) || record.version !== 1 || record.type !== "execute" ||
    typeof record.id !== "string" || !SAFE_ID.test(record.id) || typeof record.connectorId !== "string" || !SAFE_ID.test(record.connectorId) ||
    typeof record.action !== "string" || !SAFE_ACTION.test(record.action) || typeof record.grant !== "object" || record.grant === null) {
    throw new Error("WORKER_PROTOCOL_INVALID");
  }
  return record as unknown as WorkerTransportExecuteRequest;
}

function decodeResponse(value: unknown, expectedId: string): WorkerTransportResponse {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("WORKER_PROTOCOL_INVALID");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !RESPONSE_KEYS.has(key)) || record.version !== 1 || record.id !== expectedId || typeof record.ok !== "boolean") throw new Error("WORKER_PROTOCOL_INVALID");
  if (record.ok === true && !Object.hasOwn(record, "result")) throw new Error("WORKER_PROTOCOL_INVALID");
  if (record.ok === false && (typeof record.code !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(record.code))) throw new Error("WORKER_PROTOCOL_INVALID");
  return record as unknown as WorkerTransportResponse;
}

async function readOneFrame(socket: Socket, maxBytes: number, timeoutMs: number): Promise<unknown> {
  return await new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let expected: number | undefined;
    let settled = false;
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("end", onEnd);
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => finish(new Error("WORKER_PROTOCOL_TIMEOUT")), timeoutMs);
    timer.unref();
    const onError = () => finish(new Error("WORKER_PROTOCOL_IO_FAILED"));
    const onEnd = () => finish(new Error("WORKER_PROTOCOL_TRUNCATED"));
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4 && expected === undefined) {
        expected = buffer.readUInt32BE(0);
        if (expected < 1 || expected > maxBytes) { finish(new Error("WORKER_PROTOCOL_FRAME_LIMIT")); return; }
      }
      if (expected !== undefined && buffer.length >= expected + 4) {
        if (buffer.length !== expected + 4) { finish(new Error("WORKER_PROTOCOL_INVALID")); return; }
        try { finish(undefined, JSON.parse(buffer.subarray(4).toString("utf8")) as unknown); }
        catch { finish(new Error("WORKER_PROTOCOL_INVALID")); }
      }
    };
    socket.on("error", onError);
    socket.on("end", onEnd);
    socket.on("data", onData);
  });
}

export class UnixCredentialWorkerServer {
  #server: Server | null = null;
  constructor(readonly options: { socketPath: string; worker: IsolatedCredentialWorker; recoverStaleSocket?: boolean; socketAccess?: "owner" | "group"; socketGroupId?: number; maxFrameBytes?: number; timeoutMs?: number; maxConcurrent?: number }) {
    if (process.platform === "win32" || !isAbsolute(options.socketPath) || options.socketPath.includes("\0")) throw new TypeError("A Unix domain socket path is required.");
    if (options.socketAccess === "group" && (!Number.isSafeInteger(options.socketGroupId) || (options.socketGroupId ?? -1) < 0)) throw new TypeError("Group socket access requires a numeric group id.");
    const concurrency = options.maxConcurrent ?? 16;
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 1024) throw new TypeError("Worker concurrency must be between 1 and 1024.");
    const frameLimit = options.maxFrameBytes ?? 1024 * 1024;
    const timeout = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(frameLimit) || frameLimit < 1024 || frameLimit > 16 * 1024 * 1024 || !Number.isSafeInteger(timeout) || timeout < 100 || timeout > 300_000) throw new TypeError("Worker transport limits are invalid.");
  }

  async start(): Promise<void> {
    if (this.#server) throw new Error("WORKER_SERVER_ALREADY_STARTED");
    const groupAccess = this.options.socketAccess === "group";
    const socketDirectory = await ensureSocketDirectory(dirname(this.options.socketPath), groupAccess, this.options.socketGroupId);
    const max = this.options.maxFrameBytes ?? 1024 * 1024;
    const timeout = this.options.timeoutMs ?? 30_000;
    const maxConcurrent = this.options.maxConcurrent ?? 16;
    let active = 0;
    const server = createServer((socket) => {
      socket.on("error", () => { /* Stable transport denial; never log socket errors. */ });
      if (active >= maxConcurrent) { socket.destroy(); return; }
      active += 1;
      void (async () => {
        let id = "unknown";
        try {
          const request = validateRequest(await readOneFrame(socket, max, timeout));
          id = request.id;
          const result = await this.options.worker.execute({ grant: request.grant, connectorId: request.connectorId, action: request.action, input: request.input });
          socket.end(encodeFrame({ version: 1, id, ok: true, result }, max));
        } catch (error) {
          const code = error instanceof CredentialWorkerError ? error.code : "WORKER_PROTOCOL_DENIED";
          try { socket.end(encodeFrame({ version: 1, id, ok: false, code }, max)); } catch { socket.destroy(); }
        } finally { active -= 1; }
      })();
    });
    const lockRoot = await ensurePrivateDirectory(join(socketDirectory, ".worker-locks"));
    let listening = false;
    try { await withFileLock(lockRoot, "worker-start", async () => {
      try {
        const before = await lstat(this.options.socketPath);
        if (!this.options.recoverStaleSocket || !before.isSocket()) throw new Error("WORKER_SOCKET_ALREADY_EXISTS");
        if (await socketAcceptsConnections(this.options.socketPath)) throw new Error("WORKER_SOCKET_ALREADY_ACTIVE");
        const after = await lstat(this.options.socketPath);
        if (!after.isSocket() || before.dev !== after.dev || before.ino !== after.ino) throw new Error("WORKER_SOCKET_CHANGED");
        await unlink(this.options.socketPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(this.options.socketPath, () => { listening = true; server.removeListener("error", reject); resolve(); });
      });
      if (groupAccess) {
        await chown(this.options.socketPath, typeof process.getuid === "function" ? process.getuid() : -1, this.options.socketGroupId!);
        await chmod(this.options.socketPath, 0o660);
      } else {
        await chmod(this.options.socketPath, 0o600);
      }
    }); } catch (error) {
      if (listening) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        try { const info = await lstat(this.options.socketPath); if (info.isSocket()) await unlink(this.options.socketPath); } catch {}
      }
      throw error;
    }
    this.#server = server;
  }

  async stop(): Promise<void> {
    const server = this.#server;
    if (!server) return;
    this.#server = null;
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    try {
      const info = await lstat(this.options.socketPath);
      if (info.isSocket()) await unlink(this.options.socketPath);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
}

async function socketAcceptsConnections(path: string): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = createConnection(path);
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 250);
    timer.unref();
    socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
    socket.once("error", () => { clearTimeout(timer); socket.destroy(); resolve(false); });
  });
}

async function ensureSocketDirectory(path: string, groupAccess: boolean, expectedGroupId?: number): Promise<string> {
  if (!groupAccess) return await ensurePrivateDirectory(path);
  if (!isAbsolute(path) || path.includes("\0")) throw new Error("WORKER_SOCKET_DIRECTORY_INVALID");
  await mkdir(path, { recursive: true, mode: 0o710 });
  const info = await lstat(path);
  const permissions = info.mode & 0o777;
  if (!info.isDirectory() || info.isSymbolicLink() || (permissions & 0o007) !== 0 || (permissions & 0o020) !== 0 || (permissions & 0o010) === 0 ||
    (typeof process.getuid === "function" && info.uid !== process.getuid()) || info.gid !== expectedGroupId) throw new Error("WORKER_SOCKET_DIRECTORY_INVALID");
  return await realpath(path);
}

export async function probeUnixCredentialWorkerSocket(path: string, access: "owner" | "group" = "owner", groupId?: number): Promise<boolean> {
  try {
    const info = await lstat(path);
    const permissions = info.mode & 0o777;
    if (!info.isSocket() || info.isSymbolicLink() || (access === "owner" ? permissions !== 0o600 || typeof process.getuid === "function" && info.uid !== process.getuid() : permissions !== 0o660 || info.gid !== groupId)) return false;
    return await socketAcceptsConnections(path);
  } catch { return false; }
}

export class UnixCredentialWorkerClient {
  constructor(readonly options: { socketPath: string; maxFrameBytes?: number; timeoutMs?: number; newRequestId?: () => string }) {
    if (process.platform === "win32" || !isAbsolute(options.socketPath) || options.socketPath.includes("\0")) throw new TypeError("A Unix domain socket path is required.");
    const frameLimit = options.maxFrameBytes ?? 1024 * 1024; const timeout = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(frameLimit) || frameLimit < 1024 || frameLimit > 16 * 1024 * 1024 || !Number.isSafeInteger(timeout) || timeout < 100 || timeout > 300_000) throw new TypeError("Worker transport limits are invalid.");
  }

  async execute<T = unknown>(input: { connectorId: ConnectorId; action: string; grant: CredentialGrant; input: unknown }): Promise<T> {
    const id = (this.options.newRequestId ?? (() => `ipc_${globalThis.crypto.randomUUID().replaceAll("-", "")}`))();
    if (!SAFE_ID.test(id)) throw new Error("WORKER_PROTOCOL_INVALID");
    const max = this.options.maxFrameBytes ?? 1024 * 1024;
    const timeout = this.options.timeoutMs ?? 30_000;
    const socket = createConnection(this.options.socketPath);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(new Error("WORKER_PROTOCOL_TIMEOUT")); }, timeout);
      timer.unref();
      socket.once("connect", () => { clearTimeout(timer); resolve(); });
      socket.once("error", () => { clearTimeout(timer); reject(new Error("WORKER_PROTOCOL_IO_FAILED")); });
    });
    socket.write(encodeFrame({ version: 1, type: "execute", id, ...input }, max));
    const response = decodeResponse(await readOneFrame(socket, max, timeout), id);
    socket.destroy();
    if (!response.ok) throw new CredentialWorkerError(response.code as never);
    return response.result as T;
  }
}
