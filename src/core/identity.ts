const trustedActorIdBrand: unique symbol = Symbol("TrustedActorId");
const servicePrincipalIdBrand: unique symbol = Symbol("ServicePrincipalId");

/** An actor identifier that was obtained from trusted host request context. */
export type TrustedActorId = string & {
  readonly [trustedActorIdBrand]: true;
};

/** A deployment-configured, non-human principal used for unattended work. */
export type ServicePrincipalId = string & {
  readonly [servicePrincipalIdBrand]: true;
};

export interface HostActorContext {
  /** Identity asserted by the host. Model/tool input must never populate this object. */
  readonly requesterSenderId?: string | null;
  /** Trusted channel namespace paired with requesterSenderId. */
  readonly messageChannel?: string | null;
  /** Trusted receiving account namespace paired with requesterSenderId. */
  readonly agentAccountId?: string | null;
}

export type TrustedActorResult =
  | { readonly ok: true; readonly actorId: TrustedActorId }
  | {
      readonly ok: false;
      readonly code: "MISSING_TRUSTED_ACTOR" | "INVALID_TRUSTED_ACTOR";
      readonly message: string;
    };

const MAX_PRINCIPAL_ID_LENGTH = 320;
const SAFE_PRINCIPAL_ID = /^[a-z0-9][a-z0-9.!#$%&'*+/=?^_`{|}~:@-]*$/;

function normalizePrincipalId(value: string): string | null {
  const normalized = value.trim().normalize("NFKC").toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > MAX_PRINCIPAL_ID_LENGTH ||
    !SAFE_PRINCIPAL_ID.test(normalized)
  ) {
    return null;
  }
  return normalized;
}

function validateHostIdentityPart(
  value: string | null | undefined,
  label: string,
  maxLength: number,
  required: boolean,
): string | null {
  if (value === undefined || value === null || value.trim().length === 0) {
    if (required) throw new TypeError(`${label} is required.`);
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length > maxLength || /[\u0000-\u001f\u007f]/u.test(trimmed)) {
    throw new TypeError(`${label} is invalid.`);
  }
  // Preserve host identifiers exactly. Unicode normalization and lowercasing
  // can merge distinct, case-sensitive provider subjects.
  return trimmed;
}

/**
 * The sole constructor for human actor identities. Call it only with context
 * supplied by the OpenClaw host, never with tool arguments or prompt content.
 */
export function trustedActorFromHostContext(
  context: HostActorContext | null | undefined,
): TrustedActorResult {
  const assertedId = context?.requesterSenderId;
  if (typeof assertedId !== "string" || assertedId.trim().length === 0) {
    return {
      ok: false,
      code: "MISSING_TRUSTED_ACTOR",
      message: "A trusted host actor identity is required.",
    };
  }

  try {
    const senderId = validateHostIdentityPart(assertedId, "requesterSenderId", 512, true)!;
    const messageChannel = validateHostIdentityPart(
      context?.messageChannel,
      "messageChannel",
      128,
      false,
    );
    const agentAccountId = validateHostIdentityPart(
      context?.agentAccountId,
      "agentAccountId",
      160,
      false,
    );
    // A length-delimited JSON tuple prevents delimiter ambiguity and keeps
    // identical sender ids on different channels/accounts distinct.
    return {
      ok: true,
      actorId: JSON.stringify([messageChannel, agentAccountId, senderId]) as TrustedActorId,
    };
  } catch {
    return {
      ok: false,
      code: "INVALID_TRUSTED_ACTOR",
      message: "The host actor identity is not a valid principal identifier.",
    };
  }
}

/**
 * Creates an explicit service identity from trusted deployment configuration.
 * It intentionally cannot be derived from a missing human identity.
 */
export function defineServicePrincipalId(value: string): ServicePrincipalId {
  const normalized = normalizePrincipalId(value);
  if (normalized === null) {
    throw new TypeError("Invalid service principal identifier.");
  }
  return normalized as ServicePrincipalId;
}

export interface HumanPrincipal {
  readonly kind: "human";
  readonly actorId: TrustedActorId;
}

export interface ServicePrincipal {
  readonly kind: "service";
  readonly serviceId: ServicePrincipalId;
}

export type ExecutionPrincipal = HumanPrincipal | ServicePrincipal;

export function humanPrincipal(actorId: TrustedActorId): HumanPrincipal {
  return Object.freeze({ kind: "human", actorId });
}

export function servicePrincipal(serviceId: ServicePrincipalId): ServicePrincipal {
  return Object.freeze({ kind: "service", serviceId });
}

export function principalKey(principal: ExecutionPrincipal): string {
  return principal.kind === "human"
    ? `human:${principal.actorId}`
    : `service:${principal.serviceId}`;
}
