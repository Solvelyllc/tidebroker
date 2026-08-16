# Security architecture

## Purpose

Tidebroker lets one OpenClaw Gateway expose capabilities backed by the
account of the authenticated human who initiated a request. It is a routing and
authorization layer, not a secret manager and not a sandbox for untrusted
plugins.

The invariant is:

> A capability binding is selected from trusted host context and policy. Neither
> the model, tool arguments, conversation text, nor provider output can select an
> actor or credential.

Google is a useful first connector, but the design applies to CLI, MCP, and direct
HTTP connectors.

## Implementation status

Version `1.0.0` implements exact deployment-local opaque subject mapping; a
branded host-trusted selected-workspace binding with repeated membership checks;
authenticated short-lived, action- and generation-bound worker grants with replay
protection; encrypted credential and OAuth custody; audit sink integration;
revocation generation and invalidation hooks; and a fixed read-only Google/gog
Calendar connector operation; a protected bounded Unix-socket worker protocol;
and durable atomic adapters for identity, membership, encrypted records, metadata,
OAuth state, replay, and audit. The earlier identity, account-policy, MCP, CLI,
and closed-schema audit primitives remain in place.

The package now includes a supervised worker executable, owner-only key-file
loading, health checks, stale-socket recovery, protected dedicated-group socket
mode for separate OS identities, and deployment-gated OpenClaw Calendar tool
registration. It also includes a loopback-only `form_post` Google OAuth connection,
signed OIDC claim validation, worker-private dynamic account bindings, fixed-path
`gog` execution for Calendar and Gmail, and local/provider revocation.

OS/container identities and supervision, production database/KMS alternatives,
Google OAuth client registration and the selected-workspace source remain
deployment-owned. MCP schema fingerprinting/quarantine remains future work. The
installed plugin remains diagnostic-only until trusted adapters are configured;
it never falls back to ambient credentials.

## Request and execution flow

```text
identity-aware reverse proxy
  -> OpenClaw authenticated request
  -> trusted requesterSenderId + workspace binding
  -> actor/workspace authorization policy
  -> connector and account-scope policy
  -> opaque credential handle
  -> isolated connector worker
  -> provider
```

The broker copies the authenticated requester identifier into an immutable run
context before model execution. Tool schemas contain no `actor`, `user`,
`account`, `credential`, `profile`, or equivalent routing argument. A connector
receives an already authorized execution binding, not an identity suggested by
the model.

### Identity normalization

`requesterSenderId` is accepted only when OpenClaw marks it as authenticated and
the deployment has configured the relevant proxy/Gateway trust relationship.
The current library preserves a namespaced tuple of channel, receiving account,
and provider sender ID to prevent cross-channel collisions. A production
deployment must map that tuple to a stable, deployment-local opaque subject ID.
Audit events should use the opaque ID rather than an email address or OAuth
subject.

Identity normalization must:

1. Reject absent, public, synthetic, and untrusted sender identities.
2. Use an exact, canonical mapping; do not guess by display name or email domain.
3. Verify workspace membership on every run, not just when a workspace is picked.
4. Bind the actor and workspace to the run so later tool calls cannot replace
   either value.

Cloudflare Access, another identity-aware proxy, and OpenClaw configuration are
part of the deployment's trusted computing base. Header spoofing is prevented at
the network boundary: the Gateway must not be directly reachable by clients that
can supply identity headers.

## Principal types

The broker recognizes two explicit principal types:

- `human`: an authenticated interactive requester.
- `service`: a separately provisioned identity for unattended work.

Cron, heartbeat, webhook, replay, recovery, and ordinary subagent runs do **not**
inherit personal credentials merely because a conversation was originally
created by a human. They fail closed when no trusted principal is present.

A deployment may later implement delegated subagent execution, but only with a
host-issued, short-lived grant bound to actor, workspace, connector, allowed
actions, parent run, and expiry. Conversation text is never a delegation grant.
Service principals have their own policy and credentials and cannot silently
fall back to a human account.

## Authorization and account selection

Authorization evaluates this tuple:

```text
(principal, workspace, connector, action, account scope)
```

Account scopes are `personal` or `service`; a connector may support one or both.
When both are possible, deployment policy selects the default or requires an
out-of-model approval flow. The broker never uses "last account", ambient CLI
state, or the only credential it happens to find.

All misses fail closed. No mapping, disabled connector, expired grant, unknown
action, unavailable secret store, or failed policy lookup results in a denial.
There is no cross-user or company-account fallback.

## Credential custody

Credentials live outside the plugin installation directory. Production
deployments should store them in an OS keychain or dedicated secret manager and
give the Gateway only opaque handles. The preferred design performs provider
execution in a separate worker that can redeem a handle under an authorized,
short-lived request.

Minimum worker properties:

- separate config/state directory per actor and connector;
- filesystem permissions that prevent other workers from reading it;
- no inherited ambient cloud, Git, or CLI credentials;
- bounded runtime, output size, memory, and concurrency;
- a fixed executable and operation allowlist;
- secret delivery over a protected channel, never command arguments or URLs;
- sanitized structured results and errors.

Per-user directories reduce accidental crossover but are not a strong boundary
when arbitrary code in the same OS account can read them. Containers or a
separate broker service strengthen isolation. A Gateway administrator remains a
trusted operator.

## OAuth account connection

Account connection occurs in a host-owned UI or provider flow, never in chat.
OAuth state is single-use, short-lived, and integrity protected. It binds at
least:

```text
principal ID + workspace ID + connector ID + redirect target ID + PKCE challenge
+ requested scopes + nonce + issued-at/expiry
```

The callback validates state, issuer, audience/client, redirect URI, PKCE,
expiry, and nonce before exchanging the code. The resulting account is attached
to the principal from the state record, never to a browser-supplied actor field.
State is consumed atomically to prevent replay. The UI displays the provider
account and granted scopes after connection without displaying tokens.

Refresh tokens are encrypted at rest. Encryption keys are deployment-owned and
versioned for rotation. OAuth client secrets, refresh tokens, access tokens, and
authorization codes never enter prompts, tool arguments, audit events, URLs,
package contents, or normal logs.

## CLI connector safety

CLI integrations are operation adapters, not remote shells. Each registered
operation maps typed fields to a fixed executable and an argument array. The
adapter must never concatenate a shell command, run through `sh -c`, accept an
executable path, forward arbitrary flags, or use user/model data as environment
variable names.

Inputs are schema validated, length limited, and encoded as data. Where a CLI
cannot safely distinguish data from options, the connector uses an end-of-options
delimiter or stdin. The `gog` child receives only locale, private home, and a
freshly minted access token in its explicit environment; it inherits no ambient
process environment. The binary has a baked command policy and each invocation
also selects one exact command. Output is parsed to a bounded structure;
terminal control characters, credential-like fields, debug dumps, and raw stderr
are removed before reaching the model or logs.

## MCP connector safety

MCP routing pins a connector registration to an administrator-approved endpoint,
transport, server identity, and tool allowlist. The model cannot provide or
change an MCP URL. Remote transports require authenticated TLS.

On connection and reconnection, the broker verifies:

- endpoint and expected server identity;
- supported protocol version;
- tool names and input schema fingerprints;
- connector-declared read/write and approval classifications;
- that the credential binding belongs to the same principal and workspace.

Unexpected tools are hidden. A changed schema or privilege classification
quarantines the affected tool until administrator review; it is not accepted just
because the server reports the same tool name. Connection caches are keyed by
principal, workspace, connector configuration version, credential generation,
and schema fingerprint so one user's authenticated connection is never reused for
another.

## Redaction and data minimization

Secrets are prevented from reaching logs, not merely masked after logging. Code
uses structured, allowlisted events. It does not log request/response headers,
OAuth objects, environment variables, URLs with query strings, CLI command lines,
provider payloads, MCP frames, exception objects, or arbitrary metadata.

Redaction at process and transport boundaries is defense in depth. It recognizes
configured header names and provider token forms, but the design does not rely on
regular expressions to discover every secret. Production sinks should apply
their own secret scanning and retention/access controls.

The audit API in `src/audit` accepts only identifier-shaped strings, registered
action names, outcomes, correlation identifiers, and enumerated reason codes.
Unknown fields are rejected at runtime. This minimizes accidental leakage but
cannot detect a secret that happens to match identifier syntax; callers must use
deployment-registry-issued opaque IDs and convert provider errors to reason codes
before emission.

## Revocation and rotation

Every credential record has a monotonically increasing generation. Execution
bindings and connection cache keys include it. Disconnect, compromise response,
scope reduction, or key rotation increments the generation, disables redemption,
closes cached connections, and denies queued work before the next provider call.

Short-lived access tokens are refreshed inside the credential worker. A refresh
failure cannot cause fallback to another credential. Secret-store encryption-key
rotation rewraps records without exposing plaintext to the Gateway and keeps an
auditable migration state. Deployments document the maximum time for terminating
active provider operations after revocation.

## Audit event contract

An event records:

- schema version, event ID, and UTC timestamp;
- opaque actor ID and principal kind;
- opaque workspace ID;
- connector and registered action;
- `succeeded`, `denied`, or `failed` outcome;
- request/conversation/parent-event correlation IDs;
- optional enumerated reason code.

Events contain no target content, prompts, files, email addresses, provider
responses, command arguments, URLs, headers, tokens, stack traces, or free-form
messages. Audit sinks should be append-only, access controlled, encrypted, and
configured with documented retention. Event IDs support deduplication; they do
not imply exactly-once provider execution.

## Plugin and Gateway trust boundary

An OpenClaw plugin runs within the Gateway trust boundary. It can observe or
affect privileged runtime behavior and is **not** isolated from a malicious
Gateway or another malicious in-process plugin. This broker protects account
selection across honest authenticated users; it cannot protect secrets from a
host/root administrator or compromised trusted computing base.

Keeping secret redemption and provider execution out of process limits exposure,
but the worker still trusts authenticated, authorized calls from the broker. Its
protocol must independently validate operation allowlists, binding expiry,
credential generation, and replay protection.

## Update and supply-chain model

Plugin code and mutable deployment state are separate. Updates never bundle or
migrate raw credentials through the package directory. Releases should be built
from reviewed source in CI, use a locked dependency graph, publish immutable
versioned artifacts with provenance/checksums, and minimize runtime dependencies.

The plugin declares compatible OpenClaw versions. Gateway or plugin upgrades are
staged against cross-user isolation, fail-closed identity, connector schema, and
state-migration tests. Incompatibility disables the broker rather than weakening
identity checks. Rollback restores compatible code and schema while preserving
credential generations and revocations.

ClawHub users must treat this plugin and every enabled connector as trusted code.
Connector provenance, requested scopes, executables, endpoints, schema changes,
and dependency updates require review. Automatic updates should be staged rather
than applied directly to a production Gateway.
