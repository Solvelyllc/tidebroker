# Audit events

The audit event schema is deliberately small and credential-minimized. Its purpose is
to answer **who attempted which registered capability in which workspace, with
what result, and as part of which request**. It is not an application log or a
copy of provider traffic.

Example:

```json
{
  "schemaVersion": "1",
  "eventId": "evt_01JTEST",
  "occurredAt": "2026-08-15T12:00:00.000Z",
  "actor": { "id": "usr_01JTEST", "kind": "human" },
  "workspace": "ws_solvely",
  "connector": "google",
  "action": "calendar.events.list",
  "outcome": "succeeded",
  "correlation": {
    "requestId": "req_01JTEST",
    "conversationId": "conv_01JTEST"
  },
  "reasonCode": "POLICY_ALLOWED"
}
```

## Field rules

- Actor and workspace identifiers are stable, deployment-local opaque IDs. Do
  not use email addresses, provider subjects, usernames, or display names.
- Connector and action are registered names, not model-generated descriptions.
- Correlation IDs are opaque and contain no URL, query, prompt, or content.
- `reasonCode` is an enumerated code such as `NO_TRUSTED_ACTOR`,
  `WORKSPACE_DENIED`, `ACCOUNT_NOT_CONNECTED`, `CREDENTIAL_REVOKED`,
  `SCHEMA_DRIFT`, `PROVIDER_TIMEOUT`, or `OPERATION_SUCCEEDED`. It is never an
  exception or provider error message.
- `outcome` describes broker execution: `succeeded`, `denied`, or `failed`.
  Provider-side eventual effects may require separate reconciliation.

## Forbidden data

Never include credentials, OAuth state/code/token objects, cookies, headers,
environment variables, command lines or arguments, URLs, prompts, provider
request/response bodies, resource contents, filenames, email addresses, stack
traces, or arbitrary metadata. Hashing a low-entropy secret or email address does
not make it safe; use a random local mapping.

`buildAuditEvent` rejects unknown fields and exposes no free-form message field.
Callers must convert errors and policy decisions to reviewed reason codes before
building an event. Its syntax checks cannot prove an allowed-looking string is
non-secret, so identifiers must come from a deployment-owned opaque-ID registry.

## Sink requirements

Use an append-only structured sink with encryption, access control, bounded
retention, UTC timestamps, and monitoring for write failure. The sink must not
enrich events with raw request or provider data. Treat behavioral metadata as
sensitive. If audit delivery fails, mutating connector policy should define
whether execution is denied or a local durable queue is required; it must never
fall back to an unstructured debug log.

`AuditSink.ready()` is checked before mutating worker operations. Revocation is
not rolled back if an invalidation target or audit sink fails; the credential
remains disabled and the caller receives a stable failure.
