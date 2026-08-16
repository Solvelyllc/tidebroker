export type CliErrorCode =
  | "CLI_INVALID_BINDING"
  | "CLI_BINDING_MISMATCH"
  | "CLI_POLICY_DENIED"
  | "CLI_INVALID_INVOCATION"
  | "CLI_ABORTED"
  | "CLI_TIMEOUT"
  | "CLI_OUTPUT_LIMIT"
  | "CLI_SPAWN_FAILED"
  | "CLI_EXIT_NONZERO"
  | "CLI_REDACTION_FAILED";

/** An intentionally small, stable error surface that never includes argv or env. */
export class CliExecutionError extends Error {
  readonly code: CliErrorCode;
  readonly exitCode?: number;
  readonly signal?: NodeJS.Signals;

  constructor(
    code: CliErrorCode,
    message: string,
    details: {
      exitCode?: number;
      signal?: NodeJS.Signals;
    } = {},
  ) {
    super(message);
    this.name = "CliExecutionError";
    this.code = code;
    this.exitCode = details.exitCode;
    this.signal = details.signal;
  }
}
