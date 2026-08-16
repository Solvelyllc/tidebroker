import { isAbsolute } from "node:path";
import type { ActorCliBinding } from "./binding.js";
import { CliExecutionError } from "./errors.js";

export interface CliInvocation {
  /** Stable logical id, not a caller-selected executable path. */
  executable: string;
  /** Stable operation id resolved to trusted argv by policy. */
  operation: string;
  /** Untrusted operation arguments; never interpreted by a shell. */
  argv?: readonly string[];
}

export interface CliOperationAllowlist {
  /** Trusted argv inserted before caller arguments (for example, subcommands). */
  argvPrefix?: readonly string[];
  allowedFlags?: readonly string[];
  allowPositionals?: boolean;
  maxArguments?: number;
}

export interface CliExecutableAllowlist {
  /** Exact absolute executable path. PATH lookup is deliberately unsupported. */
  path: string;
  operations: Readonly<Record<string, CliOperationAllowlist>>;
}

export type CliAllowlist = Readonly<Record<string, CliExecutableAllowlist>>;

export interface ResolvedCliInvocation {
  executablePath: string;
  argv: readonly string[];
}

export interface CliPolicyContext {
  invocation: Readonly<CliInvocation>;
  binding: ActorCliBinding;
}

export type CliPolicyCallback = (
  context: CliPolicyContext,
) => ResolvedCliInvocation | Promise<ResolvedCliInvocation>;

const secretFlags = new Set([
  "--access-token",
  "--api-key",
  "--authorization",
  "--client-secret",
  "--credential",
  "--credentials",
  "--password",
  "--private-key",
  "--refresh-token",
  "--secret",
  "--token",
]);

function isCredentialFlag(flag: string): boolean {
  if (secretFlags.has(flag)) return true;
  const words = flag.replace(/^-+/, "");
  return /(?:^|-)(?:api-key|access-token|auth-token|authorization|client-secret|credentials?|password|private-key|refresh-token|secret|token)(?:-|$)/.test(
    words,
  );
}

function flagName(argument: string): string | undefined {
  if (!argument.startsWith("-") || argument === "-") return undefined;
  return argument.split("=", 1)[0]?.toLowerCase();
}

function validatePrimitive(value: string, label: string): void {
  if (typeof value !== "string" || value.includes("\0")) {
    throw new CliExecutionError(
      "CLI_INVALID_INVOCATION",
      `${label} must be a string without NUL bytes`,
    );
  }
}

export function validateResolvedInvocation(resolved: ResolvedCliInvocation): void {
  if (!isAbsolute(resolved.executablePath) || resolved.executablePath.includes("\0")) {
    throw new CliExecutionError(
      "CLI_POLICY_DENIED",
      "CLI policy must resolve an absolute executable path",
    );
  }
  for (const argument of resolved.argv) {
    validatePrimitive(argument, "CLI argument");
    const flag = flagName(argument);
    if (flag && isCredentialFlag(flag)) {
      throw new CliExecutionError(
        "CLI_POLICY_DENIED",
        "Credential-bearing CLI flags are prohibited",
      );
    }
  }
}

function validateArguments(
  argv: readonly string[],
  operation: CliOperationAllowlist,
): void {
  const max = operation.maxArguments ?? 64;
  if (argv.length > max) {
    throw new CliExecutionError("CLI_POLICY_DENIED", "CLI argument count exceeds policy");
  }

  const allowedFlags = new Set(operation.allowedFlags ?? []);
  for (const argument of argv) {
    validatePrimitive(argument, "CLI argument");
    const flag = flagName(argument);
    if (!flag) {
      if (!operation.allowPositionals) {
        throw new CliExecutionError("CLI_POLICY_DENIED", "CLI positional argument denied by policy");
      }
      continue;
    }
    if (isCredentialFlag(flag)) {
      throw new CliExecutionError(
        "CLI_POLICY_DENIED",
        "Credential-bearing CLI flags are prohibited",
      );
    }
    if (!allowedFlags.has(flag)) {
      throw new CliExecutionError("CLI_POLICY_DENIED", "CLI flag denied by policy");
    }
  }
}

export function createAllowlistPolicy(allowlist: CliAllowlist): CliPolicyCallback {
  return ({ invocation }) => {
    validatePrimitive(invocation.executable, "CLI executable id");
    validatePrimitive(invocation.operation, "CLI operation id");
    const executable = allowlist[invocation.executable];
    const operation = executable?.operations[invocation.operation];
    if (!executable || !operation || !isAbsolute(executable.path)) {
      throw new CliExecutionError("CLI_POLICY_DENIED", "CLI executable or operation denied by policy");
    }
    const argv = invocation.argv ?? [];
    validateArguments(argv, operation);
    const resolved = {
      executablePath: executable.path,
      argv: [...(operation.argvPrefix ?? []), ...argv],
    };
    validateResolvedInvocation(resolved);
    return resolved;
  };
}
