/**
 * Closed-schema, credential-minimized security audit events.
 *
 * This module intentionally has no generic metadata, message, headers, command,
 * arguments, URL, or error fields. Provider responses and credentials must never
 * be passed to the audit layer.
 */

export const AUDIT_SCHEMA_VERSION = "1" as const;

export type AuditActorKind = "human" | "service";
export type AuditOutcome = "succeeded" | "denied" | "failed";

export interface AuditActor {
  /** Stable, deployment-local, opaque subject identifier (not an email address). */
  id: string;
  kind: AuditActorKind;
}

export interface AuditCorrelation {
  /** Identifier assigned at the trusted request boundary. */
  requestId: string;
  /** Optional opaque conversation identifier. */
  conversationId?: string;
  /** Optional parent event for delegated operations. */
  parentEventId?: string;
}

export interface AuditEvent {
  schemaVersion: typeof AUDIT_SCHEMA_VERSION;
  eventId: string;
  occurredAt: string;
  actor: Readonly<AuditActor>;
  /** Stable, opaque workspace identifier. */
  workspace: string;
  /** Registered connector slug. */
  connector: string;
  /** Registered, non-secret operation name such as `calendar.events.list`. */
  action: string;
  outcome: AuditOutcome;
  correlation: Readonly<AuditCorrelation>;
  /** Enumerated machine-readable reason; never a provider error message. */
  reasonCode?: string;
}

export interface BuildAuditEventInput {
  actor: AuditActor;
  workspace: string;
  connector: string;
  action: string;
  outcome: AuditOutcome;
  correlation: AuditCorrelation;
  reasonCode?: string;
}

export interface AuditEventBuilderOptions {
  now?: () => Date;
  newEventId?: () => string;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ACTION = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,15}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;

const TOP_LEVEL_KEYS = new Set([
  "actor",
  "workspace",
  "connector",
  "action",
  "outcome",
  "correlation",
  "reasonCode",
]);
const ACTOR_KEYS = new Set(["id", "kind"]);
const CORRELATION_KEYS = new Set(["requestId", "conversationId", "parentEventId"]);

function assertPlainRecord(value: unknown, field: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${field} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${field} must be a plain object`);
  }
}

function assertOnlyKeys(record: Record<string, unknown>, allowed: Set<string>, field: string): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new TypeError(`${field} contains unsupported field: ${key}`);
    }
  }
}

function assertIdentifier(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${field} must be an opaque identifier of 1-128 safe characters`);
  }
}

function assertAction(value: unknown): asserts value is string {
  if (typeof value !== "string" || !ACTION.test(value)) {
    throw new TypeError("action must be a registered lower-case operation name");
  }
}

function assertReasonCode(value: unknown): asserts value is string {
  if (typeof value !== "string" || !REASON_CODE.test(value)) {
    throw new TypeError("reasonCode must be an enumerated upper-case code");
  }
}

function defaultEventId(): string {
  const randomUuid = globalThis.crypto?.randomUUID;
  if (!randomUuid) {
    throw new Error("crypto.randomUUID is required to build audit events");
  }
  return randomUuid.call(globalThis.crypto);
}

/**
 * Build an immutable event from a closed set of intended non-secret fields.
 *
 * Runtime key checks protect JavaScript callers and deserialized input from
 * accidentally attaching credentials or provider payloads. Identifier syntax
 * cannot prove a string is non-secret: identifiers must be pseudonymized and
 * issued by a deployment-owned registry before this function is called.
 */
export function buildAuditEvent(
  input: BuildAuditEventInput,
  options: AuditEventBuilderOptions = {},
): Readonly<AuditEvent> {
  assertPlainRecord(input, "audit event input");
  assertOnlyKeys(input, TOP_LEVEL_KEYS, "audit event input");

  assertPlainRecord(input.actor, "actor");
  assertOnlyKeys(input.actor, ACTOR_KEYS, "actor");
  assertIdentifier(input.actor.id, "actor.id");
  if (input.actor.kind !== "human" && input.actor.kind !== "service") {
    throw new TypeError("actor.kind must be human or service");
  }

  assertIdentifier(input.workspace, "workspace");
  assertIdentifier(input.connector, "connector");
  assertAction(input.action);
  if (!(["succeeded", "denied", "failed"] as const).includes(input.outcome)) {
    throw new TypeError("outcome must be succeeded, denied, or failed");
  }

  assertPlainRecord(input.correlation, "correlation");
  assertOnlyKeys(input.correlation, CORRELATION_KEYS, "correlation");
  assertIdentifier(input.correlation.requestId, "correlation.requestId");
  if (input.correlation.conversationId !== undefined) {
    assertIdentifier(input.correlation.conversationId, "correlation.conversationId");
  }
  if (input.correlation.parentEventId !== undefined) {
    assertIdentifier(input.correlation.parentEventId, "correlation.parentEventId");
  }
  if (input.reasonCode !== undefined) assertReasonCode(input.reasonCode);

  const eventId = (options.newEventId ?? defaultEventId)();
  assertIdentifier(eventId, "eventId");
  const occurredAt = (options.now ?? (() => new Date()))().toISOString();

  const actor = Object.freeze({ id: input.actor.id, kind: input.actor.kind });
  const correlation = Object.freeze({
    requestId: input.correlation.requestId,
    ...(input.correlation.conversationId === undefined
      ? {}
      : { conversationId: input.correlation.conversationId }),
    ...(input.correlation.parentEventId === undefined
      ? {}
      : { parentEventId: input.correlation.parentEventId }),
  });

  return Object.freeze({
    schemaVersion: AUDIT_SCHEMA_VERSION,
    eventId,
    occurredAt,
    actor,
    workspace: input.workspace,
    connector: input.connector,
    action: input.action,
    outcome: input.outcome,
    correlation,
    ...(input.reasonCode === undefined ? {} : { reasonCode: input.reasonCode }),
  });
}

export type { AuditSink } from "./sink.js";
export { MemoryAuditSink } from "./sink.js";
