# Threat model

> **Status:** This is the release-gating threat model for the target production
> broker. Version `1.0.0` implements the operational controls described in
> `SECURITY-ARCHITECTURE.md`, including trusted workspace binding, authenticated
> credential-worker grants, OAuth custody, audit delivery contracts, and
> revocation, protected local transport, and durable file adapters. OS/container
> deployment, a real-provider smoke test, and MCP schema quarantine remain gates.

## Scope and security goals

This threat model covers the actor-scoped capability broker, connector workers,
credential store integration, OAuth callback handling, requester-scoped MCP
connections, CLI adapters, and security audit events.

Security goals:

1. A request can use only credentials authorized for its trusted principal and
   workspace.
2. Model-controlled data cannot select or change the actor, workspace,
   credential, executable, or MCP endpoint.
3. Non-interactive work has no personal authority unless the host supplies an
   explicit, constrained delegation or service principal.
4. Credentials do not enter model context, tool-visible results, audit events,
   logs, URLs, or command arguments.
5. Revocation and policy changes invalidate future redemption and cached
   connections.
6. Connector and Gateway updates fail closed when identity or schema assumptions
   change.

Availability, correctness of third-party provider data, compromise of the host or
Gateway administrator, and malicious behavior by a provider are not guarantees of
the broker. Content returned from a provider remains untrusted and may contain
prompt injection.

## Assets

- OAuth refresh/access tokens, API keys, session cookies, and CLI auth state.
- The mapping between authenticated subjects, workspaces, and credential handles.
- Workspace membership and connector/action policy.
- Service-principal identities and delegated grants.
- Integrity of connector executable, MCP endpoint, and tool schemas.
- Audit-event integrity and user privacy.
- Provider resources reachable through connected accounts.

## Trust boundaries

```text
browser | identity proxy | Gateway/plugin | policy + secret store | worker | provider
                                        \-> audit sink
```

- Browser input, conversation content, model output, tool arguments, provider
  content, CLI output, MCP server descriptions, and package-registry content are
  untrusted.
- The correctly configured identity proxy, OpenClaw authenticated run context,
  broker policy engine, secret store, connector worker, and deployment
  administrator are trusted components.
- The Gateway and in-process plugins share one trust boundary. Plugin installation
  is privileged code installation, not content import.
- Network identity headers are trusted only on the protected proxy-to-Gateway
  route. Direct Gateway reachability invalidates that assumption.

## Adversaries

- An authenticated user attempting to access another user's or a service
  principal's account.
- Prompt injection in chat, documents, email, web pages, or MCP tool descriptions.
- A malicious or compromised MCP server or CLI dependency.
- An attacker replaying or swapping OAuth callbacks.
- A compromised package, update channel, connector, or transitive dependency.
- An operator mistake that leaves ambient credentials or permissive fallback.
- A log reader attempting to recover credentials or sensitive user activity.

Host/root and trusted Gateway administrator compromise is out of the isolation
guarantee, but out-of-process credential custody should reduce blast radius.

## Threats and required controls

| Threat | Required control | Verification |
|---|---|---|
| Model requests `actor=operator-b` during operator A's run | Actor is absent from tool schemas and sourced only from trusted `requesterSenderId`; immutable run binding | Adversarial tool-call test proves supplied identity is rejected/ignored |
| Spoofed identity header | Gateway reachable only from identity proxy; strip inbound identity headers; validate proxy trust | Direct-origin request cannot create authenticated context |
| Workspace-picker tampering | Server-side membership check on every run and tool execution | Unauthorized workspace ID is denied |
| Missing identity uses ambient credentials | No global/default/last-user fallback; capability omitted or denied | Cron, heartbeat, public, replay, and unauthenticated tests fail closed |
| Subagent gains parent's full credentials | Default deny; optional short-lived action-scoped host grant with parent correlation | Ordinary subagent has no binding; expired or broadened grant fails |
| Service automation impersonates a human | Explicit service principal and separate credentials/policy | Service audit actor kind and account remain distinct |
| Cross-user cache reuse | Cache key includes principal, workspace, connector version, credential generation, and schema fingerprint | Concurrent two-user tests cannot observe or use the other connection |
| TOCTOU after authorization | Worker validates signed binding, expiry, operation, generation, and replay nonce immediately before redemption | Revocation between queue and execution denies provider call |
| OAuth login swapping/replay | Integrity-protected single-use state bound to principal/workspace/connector/client/scopes/PKCE/expiry/nonce | Callback mismatch and second use fail |
| CLI argument or shell injection | Fixed executable, no shell, typed allowlisted operation, argument array, stdin/`--`, bounded environment | Metacharacter, leading-dash, newline, path, and oversized-input tests |
| CLI reads another profile | Per-principal state directory and preferably isolated OS/container worker; no ambient auth | Filesystem and concurrency isolation tests |
| Model selects malicious MCP server | Administrator-pinned endpoint, authenticated TLS, no URL input | Endpoint field absent; redirect/server identity mismatch denied |
| MCP tool changes meaning or schema | Allowlisted tool names plus schema/privilege fingerprints; quarantine on drift | Reconnect with changed schema disables tool |
| MCP connection survives account rotation | Credential generation in cache key; close on revoke/rotate | Old generation cannot execute after invalidation |
| Provider output leaks a token | Structured allowlist parser; output bounds; credential-field removal | Synthetic token fields and debug dumps never reach result/log |
| Exception/log leaks request or environment | Reason codes, no exception-object serialization, no headers/URLs/commands/payloads | Sink-capture tests scan all error paths |
| Audit API used as secret exfiltration | Closed schema, registry-issued opaque identifiers, enumerated reason codes, reject unknown keys | Runtime tests reject token/header/error/metadata fields; production registry prevents arbitrary identifiers |
| Malicious connector/plugin reads secrets | Treat plugins as trusted code; minimize installed plugins; external secret broker and scoped worker | Package review, provenance, capability review |
| Compromised update changes policy | Locked dependencies, immutable signed/provenanced releases, staged compatibility tests and rollback | Reproducible artifact checks; upgrade isolation suite |
| Revoked credential falls back to company account | Generation invalidation and absolute no-fallback rule | Revocation test returns denial despite other usable accounts |
| Prompt injection requests destructive action | Provider content remains untrusted; per-action policy and host-owned approval for writes | Injected text cannot alter binding or bypass approval |

## Security invariants

These invariants are release blockers:

- `requesterSenderId` is read from host context, never tool/model input.
- Actor and workspace are bound before any provider-controlled content is read.
- No trusted identity means no personal connector binding.
- Account resolution returns one explicitly authorized handle or denial.
- A connector cannot receive raw credentials unless it is the designated isolated
  redemption worker.
- Production callers use only registry-issued opaque IDs in audit-event fields;
  the current syntax validator alone cannot identify every secret-shaped string.
- Every attempted provider operation must emit a correlated success, denial, or
  failure event without provider content before an operational release.
- Revoked generations cannot open or reuse connections.
- MCP schema drift and unsupported Gateway versions disable affected tools.

## Required test matrix

Before a public release, tests cover:

1. Two-operator concurrency across every connector transport.
2. Model-supplied actor, workspace, account, executable, endpoint, and credential
   values.
3. Missing/invalid proxy identity and unauthorized workspace membership.
4. Cron, heartbeat, public session, replay, ordinary subagent, explicit service
   principal, and expired delegated grant.
5. OAuth mismatch, expiry, wrong PKCE, replay, concurrent callback, and reduced
   scope.
6. CLI metacharacters, option injection, path traversal, environment attacks,
   hangs, excessive output, and malicious stderr.
7. MCP endpoint redirect, certificate/server mismatch, new tool, changed input
   schema, changed read/write classification, and reconnect after rotation.
8. Disconnect and revocation while queued, running, cached, and refreshing.
9. Secret canaries placed in every credential, header, response, exception,
   environment, and CLI/MCP output; assert none reaches model results or sinks.
10. Supported Gateway upgrade, unsupported Gateway version, connector migration,
    failed migration, rollback, and credential-state preservation.

Security tests use synthetic canaries only. Real credentials must never be added
to fixtures, snapshots, CI variables visible to forks, bug reports, or chat.

## Residual risks

- A malicious or compromised Gateway, host administrator, or in-process plugin
  can bypass plugin-level controls.
- Provider-returned content can manipulate the model; binding isolation does not
  solve prompt injection or authorize destructive operations.
- A permitted action may expose sensitive business data even without exposing a
  token. Policy, approval, and result filtering remain necessary.
- CLI tools may write credentials or sensitive debug data outside their expected
  profile directory; connectors require tool-specific review.
- Secret-redaction patterns are incomplete by nature. Prevention and closed
  schemas are primary controls.
- Audit records disclose behavioral metadata. Access and retention must be
  proportional to the deployment's privacy requirements.

## Vulnerability handling

Reports should contain connector/version, impact, and synthetic reproduction
steps, but no live tokens, OAuth codes, account data, or production logs. A
credential-isolation defect is treated as high severity: disable the affected
  connector, revoke exposed credential generations, preserve minimized audit
evidence, publish a fixed immutable release, and document upgrade action.
