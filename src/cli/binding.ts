import { realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { CliExecutionError } from "./errors.js";
import { principalKey } from "../core/identity.js";
import type { ConnectorExecutionContext } from "../core/connector.js";

const bindingBrand: unique symbol = Symbol("ActorCliBinding");
interface BindingMetadata {
  readonly configRoot: string;
  readonly configDirectory: string;
  readonly executionContext: ConnectorExecutionContext;
}

const bindingMetadata = new WeakMap<object, BindingMetadata>();

export interface ActorCliBinding {
  /** Opaque at the API boundary; only the executor consumes this value. */
  readonly [bindingBrand]: true;
}

export interface CreateActorCliBindingOptions {
  /** Immutable context produced from the exact authorized account binding. */
  executionContext: ConnectorExecutionContext;
  /** Existing actor-specific directory containing only that actor's CLI state. */
  configDirectory: string;
  /** Existing root under which every permitted actor directory must reside. */
  configRoot: string;
}

function isWithin(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!child.startsWith("..") && !isAbsolute(child));
}

function snapshotExecutionContext(
  context: ConnectorExecutionContext,
): ConnectorExecutionContext {
  const principal = context.principal.kind === "human"
    ? Object.freeze({ kind: "human" as const, actorId: context.principal.actorId })
    : Object.freeze({ kind: "service" as const, serviceId: context.principal.serviceId });
  return Object.freeze({
    principal,
    workspaceId: context.workspaceId,
    accountId: context.accountId,
    credentialHandle: context.credentialHandle,
  });
}

/**
 * Resolve symlinks and prove that a config directory is contained by its declared
 * root. The returned binding cannot be assembled by ordinary TypeScript callers.
 */
export async function createActorCliBinding(
  options: CreateActorCliBindingOptions,
): Promise<ActorCliBinding> {
  if (
    !options.configDirectory ||
    !options.configRoot ||
    options.configDirectory.includes("\0") ||
    options.configRoot.includes("\0") ||
    !isAbsolute(options.configDirectory) ||
    !isAbsolute(options.configRoot)
  ) {
    throw new CliExecutionError(
      "CLI_INVALID_BINDING",
      "CLI config root and directory must be absolute, non-empty paths",
    );
  }

  try {
    const [root, directory] = await Promise.all([
      realpath(resolve(options.configRoot)),
      realpath(resolve(options.configDirectory)),
    ]);
    const directoryStat = await stat(directory);
    if (!directoryStat.isDirectory() || !isWithin(root, directory)) {
      throw new CliExecutionError(
        "CLI_INVALID_BINDING",
        "CLI config directory is outside the permitted root or is not a directory",
      );
    }

    const binding: ActorCliBinding = {
      [bindingBrand]: true as const,
    };
    bindingMetadata.set(binding, Object.freeze({
      configRoot: root,
      configDirectory: directory,
      executionContext: snapshotExecutionContext(options.executionContext),
    }));
    return Object.freeze(binding);
  } catch (error) {
    if (error instanceof CliExecutionError) throw error;
    throw new CliExecutionError(
      "CLI_INVALID_BINDING",
      "CLI config directory could not be validated",
    );
  }
}

export function assertActorCliBinding(binding: ActorCliBinding): void {
  if (
    !binding ||
    binding[bindingBrand] !== true ||
    !bindingMetadata.has(binding)
  ) {
    throw new CliExecutionError("CLI_INVALID_BINDING", "Invalid CLI execution binding");
  }
}

/** Internal executor access; intentionally not exported from the public barrel. */
function sameExecutionContext(
  left: ConnectorExecutionContext,
  right: ConnectorExecutionContext,
): boolean {
  return principalKey(left.principal) === principalKey(right.principal) &&
    left.workspaceId === right.workspaceId &&
    left.accountId === right.accountId &&
    left.credentialHandle === right.credentialHandle;
}

/** Internal executor access; intentionally not exported from the public barrel. */
export async function validateActorCliBindingForExecution(
  binding: ActorCliBinding,
  executionContext: ConnectorExecutionContext,
): Promise<string> {
  assertActorCliBinding(binding);
  const metadata = bindingMetadata.get(binding)!;
  if (!sameExecutionContext(metadata.executionContext, executionContext)) {
    throw new CliExecutionError(
      "CLI_BINDING_MISMATCH",
      "CLI binding does not match the authorized execution context",
    );
  }

  try {
    const [root, directory] = await Promise.all([
      realpath(metadata.configRoot),
      realpath(metadata.configDirectory),
    ]);
    const directoryStat = await stat(directory);
    if (
      root !== metadata.configRoot ||
      directory !== metadata.configDirectory ||
      !directoryStat.isDirectory() ||
      !isWithin(root, directory)
    ) {
      throw new CliExecutionError(
        "CLI_INVALID_BINDING",
        "CLI config binding changed after authorization",
      );
    }
    return directory;
  } catch (error) {
    if (error instanceof CliExecutionError) throw error;
    throw new CliExecutionError(
      "CLI_INVALID_BINDING",
      "CLI config binding could not be revalidated",
    );
  }
}
