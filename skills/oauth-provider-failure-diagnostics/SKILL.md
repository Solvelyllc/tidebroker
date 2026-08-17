---
name: "oauth-provider-failure-diagnostics"
description: "Diagnose generic OAuth connector failures by isolating refresh and provider stages without exposing credential material."
---

# OAuth Provider Failure Diagnostics

Use this procedure when an OAuth connection or provider operation reports only a generic failure.

1. Locate the active worker's structured audit from its effective service launch configuration. Read the referenced worker configuration for the audit root without exposing secrets, inspect one event's keys to identify the real timestamp and outcome fields, then filter events newer than the diagnostic or restart boundary. Separate authorization callback rejection, credential redemption, token refresh, and provider execution by outcome and reason code. Complete when current-run evidence identifies the failure boundary without reading credential payloads or relying on stale events.

2. Correlate the failure timestamp with fresh egress-proxy records before testing credentials. Treat the absence of a token-endpoint request as evidence that the flow stopped before credential redemption; inspect the authorization callback path next. Treat observed token and API tunnels as stage boundaries, not proof of authorization success. Complete when egress evidence places the failure before redemption, during refresh, or during provider execution.

3. Preserve safe provider detail at the authorization callback. Parse the provider error separately from the authorization code, map recognized error values to bounded internal reason codes, collapse unknown values to one generic provider-error code, and omit error descriptions and OAuth material from pages, audits, logs, and exceptions. Test recognized, unknown, and missing-error cases. Complete when a rejected callback yields a bounded reason code while successful callbacks retain the existing state and code checks.

4. Handle invalid local form or callback state as a pre-provider failure. Confirm whether the failed attempt created OAuth state and reached any provider endpoint. When it did neither, reproduce the onboarding page GET and start-form POST locally with the same origin while emitting only statuses, redirect presence, and a bounded reason; defer another consent attempt until this local envelope succeeds. Keep the listener available after stale-form or origin errors, return a reload path, accept only configured canonical loopback origins, and use a distinct attempt URL so an old tab cannot collide with a new session. After a restart or new attempt, discard previously opened pages and initiate the flow with fresh state. Complete when the local GET→POST redirects successfully and a fresh browser attempt either passes state validation or returns a bounded pre-provider reason.

5. Refine generic post-exchange failures with bounded stage codes. When fresh proxy evidence shows successful token and key-set requests but no credential write, isolate token HTTP/schema validation, ID-token format/header/key/claims validation, issuer/audience/nonce binding, credential presence, and exact scope reconciliation. Propagate only allowlisted code-shaped reasons to the audit and user page; keep token responses, claims, scopes, and credential material private. Add focused tests and build the worker. Complete when one bounded reason identifies the failed post-exchange check without exposing OAuth material.

6. Verify provider reachability without authentication. Resolve the provider hosts and make unauthenticated requests that report status only. Treat the response as network evidence, not authorization evidence. Complete when DNS and HTTP reachability are confirmed or ruled out.

7. Read the worker operation and credential-store implementation. Identify each outbound provider stage, the credential material shape, and the point where detailed errors become generic. Complete when the diagnostic can mirror the real execution path.

8. Investigate strict output-schema failures against the exact installed provider CLI version. Inspect the command's serialized output path, including transformations and security wrappers, then compare its root and projected-record fields with the connector allowlist. Add only the exact documented wrapper shape, validate every marker field and value, preserve rejection of arbitrary fields, and test accepted and malformed records. Complete when the parser accepts the observed safe envelope and rejects altered metadata or unknown fields.

9. Run the diagnostic as the worker service identity, using the active deployment modules and effective proxy environment. Use the existing secure credential path and perform each provider stage in order. Emit only the failing stage, HTTP status, and a strictly validated provider error class. Keep tokens, client values, account identity, authorization headers, and response bodies out of output and transcripts. Complete when the diagnostic passes credential-store ownership checks and returns a bounded stage result.

10. Correlate each diagnostic attempt with fresh egress-proxy records. Distinguish an allowed token-refresh tunnel, a denied service-specific API host, and an allowed API tunnel followed by a provider failure. When the proxy denies an observed provider host, add only that required host to the allowlist, validate the configuration, reload the proxy, and rerun the same operation. Complete when the required outbound stages are allowed or the remaining failure is proven to occur after egress.

11. Apply the provider-specific recovery only after the failing stage is proven. For Google Calendar `accessNotConfigured`, follow [references/google-calendar.md](references/google-calendar.md). Complete when the recovery target is tied to the diagnosed OAuth project rather than guessed configuration.

12. Re-run the original connector operation after recovery. Verify a successful worker result and corresponding audit outcome. Complete when the end-to-end path succeeds through the normal worker boundary.
