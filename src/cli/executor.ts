import { spawn } from "node:child_process";
import type { ActorCliBinding } from "./binding.js";
import { assertActorCliBinding, validateActorCliBindingForExecution } from "./binding.js";
import type { ConnectorExecutionContext } from "../core/connector.js";
import { CliExecutionError } from "./errors.js";
import type {
  CliInvocation,
  CliPolicyCallback,
  ResolvedCliInvocation,
} from "./policy.js";
import { validateResolvedInvocation } from "./policy.js";

export type CliOutputStream = "stdout" | "stderr";
export type CliRedactor = (
  text: string,
  stream: CliOutputStream,
) => string | Promise<string>;

export interface CliExecutorOptions {
  policy: CliPolicyCallback;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Required provider-aware sanitizer. There is no raw-output default. */
  redact: CliRedactor;
  /** Env names set to the validated config directory. Values are never caller supplied. */
  configDirectoryEnv?: readonly string[];
}

export interface CliExecuteOptions {
  signal?: AbortSignal;
}

export interface CliExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: 0;
}

const defaultTimeoutMs = 30_000;
const defaultMaxOutputBytes = 1024 * 1024;
const envNamePattern = /^[A-Z_][A-Z0-9_]*$/;

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CliExecutionError("CLI_INVALID_INVOCATION", `${label} must be a positive integer`);
  }
  return value;
}

async function redactOutput(
  redactor: CliRedactor,
  stdout: string,
  stderr: string,
  maxOutputBytes: number,
): Promise<{ stdout: string; stderr: string }> {
  try {
    const output = {
      stdout: await redactor(stdout, "stdout"),
      stderr: await redactor(stderr, "stderr"),
    };
    if (
      typeof output.stdout !== "string" ||
      typeof output.stderr !== "string"
    ) {
      throw new Error("redactor returned a non-string");
    }
    if (Buffer.byteLength(output.stdout) + Buffer.byteLength(output.stderr) > maxOutputBytes) {
      throw new CliExecutionError("CLI_OUTPUT_LIMIT", "Redacted CLI output limit exceeded");
    }
    return output;
  } catch (error) {
    if (error instanceof CliExecutionError) throw error;
    throw new CliExecutionError("CLI_REDACTION_FAILED", "CLI output redaction failed");
  }
}

function makeEnvironment(
  configDirectory: string,
  names: readonly string[],
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
  };
  for (const name of names) {
    if (
      !envNamePattern.test(name) ||
      (name !== "HOME" &&
        name !== "XDG_CONFIG_HOME" &&
        !name.endsWith("_CONFIG_DIR") &&
        !name.endsWith("_CONFIG_HOME") &&
        !name.endsWith("_HOME"))
    ) {
      throw new CliExecutionError(
        "CLI_INVALID_INVOCATION",
        "CLI config environment name is invalid",
      );
    }
    env[name] = configDirectory;
  }
  return env;
}

export class ActorCliExecutor {
  readonly #policy: CliPolicyCallback;
  readonly #timeoutMs: number;
  readonly #maxOutputBytes: number;
  readonly #redact: CliRedactor;
  readonly #configDirectoryEnv: readonly string[];

  constructor(options: CliExecutorOptions) {
    this.#policy = options.policy;
    if (typeof options.redact !== "function") {
      throw new CliExecutionError(
        "CLI_INVALID_INVOCATION",
        "A CLI output sanitizer is required",
      );
    }
    this.#timeoutMs = positiveInteger(options.timeoutMs ?? defaultTimeoutMs, "CLI timeout");
    this.#maxOutputBytes = positiveInteger(
      options.maxOutputBytes ?? defaultMaxOutputBytes,
      "CLI output limit",
    );
    this.#redact = options.redact;
    this.#configDirectoryEnv = Object.freeze([...(options.configDirectoryEnv ?? ["HOME"])]);
  }

  async execute(
    binding: ActorCliBinding,
    executionContext: ConnectorExecutionContext,
    invocation: CliInvocation,
    options: CliExecuteOptions = {},
  ): Promise<CliExecutionResult> {
    assertActorCliBinding(binding);
    if (options.signal?.aborted) {
      throw new CliExecutionError("CLI_ABORTED", "CLI execution aborted");
    }

    let resolved: ResolvedCliInvocation;
    try {
      const safeInvocation = Object.freeze({
        ...invocation,
        argv: invocation.argv ? Object.freeze([...invocation.argv]) : undefined,
      });
      resolved = await this.#policy({ invocation: safeInvocation, binding });
      validateResolvedInvocation(resolved);
    } catch (error) {
      if (error instanceof CliExecutionError) throw error;
      throw new CliExecutionError("CLI_POLICY_DENIED", "CLI policy denied execution");
    }

    if (options.signal?.aborted) {
      throw new CliExecutionError("CLI_ABORTED", "CLI execution aborted");
    }
    const configDirectory = await validateActorCliBindingForExecution(
      binding,
      executionContext,
    );
    if (options.signal?.aborted) {
      throw new CliExecutionError("CLI_ABORTED", "CLI execution aborted");
    }
    const env = makeEnvironment(configDirectory, this.#configDirectoryEnv);
    return await this.#spawn(resolved, configDirectory, env, options.signal);
  }

  async #spawn(
    resolved: ResolvedCliInvocation,
    configDirectory: string,
    env: NodeJS.ProcessEnv,
    signal?: AbortSignal,
  ): Promise<CliExecutionResult> {
    return await new Promise<CliExecutionResult>((resolve, reject) => {
      let child;
      try {
        child = spawn(resolved.executablePath, [...resolved.argv], {
          cwd: configDirectory,
          env,
          shell: false,
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
          detached: process.platform !== "win32",
        });
      } catch {
        reject(new CliExecutionError("CLI_SPAWN_FAILED", "CLI process could not be started"));
        return;
      }
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let settled = false;
      let terminalError: CliExecutionError | undefined;

      const terminate = (error: CliExecutionError): void => {
        if (terminalError) return;
        terminalError = error;
        if (process.platform !== "win32" && child.pid !== undefined) {
          try {
            process.kill(-child.pid, "SIGKILL");
            return;
          } catch {
            // Fall through if the group is already gone.
          }
        }
        // Windows requires a Job Object/container for a strong descendant
        // boundary. This fallback terminates only the immediate process.
        child.kill("SIGKILL");
      };
      const timer = setTimeout(
        () => terminate(new CliExecutionError("CLI_TIMEOUT", "CLI execution timed out")),
        this.#timeoutMs,
      );
      timer.unref();
      const onAbort = (): void =>
        terminate(new CliExecutionError("CLI_ABORTED", "CLI execution aborted"));
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) onAbort();

      child.stdout.on("data", (chunk: Buffer) => {
        stdoutBytes += chunk.length;
        if (stdoutBytes + stderrBytes > this.#maxOutputBytes) {
          terminate(new CliExecutionError("CLI_OUTPUT_LIMIT", "CLI output limit exceeded"));
          return;
        }
        stdout.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderrBytes += chunk.length;
        if (stdoutBytes + stderrBytes > this.#maxOutputBytes) {
          terminate(new CliExecutionError("CLI_OUTPUT_LIMIT", "CLI output limit exceeded"));
          return;
        }
        stderr.push(chunk);
      });
      child.on("error", (error) => {
        terminalError ??= new CliExecutionError(
          "CLI_SPAWN_FAILED",
          "CLI process could not be started",
        );
      });
      child.on("close", (exitCode, childSignal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);

        void (async () => {
          if (terminalError) throw terminalError;
          const output = await redactOutput(
            this.#redact,
            Buffer.concat(stdout).toString("utf8"),
            Buffer.concat(stderr).toString("utf8"),
            this.#maxOutputBytes,
          );
          if (exitCode !== 0) {
            throw new CliExecutionError("CLI_EXIT_NONZERO", "CLI process exited unsuccessfully", {
              exitCode: exitCode ?? undefined,
              signal: childSignal ?? undefined,
            });
          }
          return { ...output, exitCode: 0 as const };
        })().then(resolve, reject);
      });
    });
  }
}
