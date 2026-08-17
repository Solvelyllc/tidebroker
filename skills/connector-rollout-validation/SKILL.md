---
name: "connector-rollout-validation"
description: "Validate connector rollouts with artifact, per-binding, and fail-closed isolation checks."
---

# Connector rollout validation

Validate a deployed connector without exposing provider data or confusing stale credentials with rollout defects.

1. Validate each runtime layer independently: worker service health, loaded artifact identity, plugin registration, configured tool allowlisting, and gateway-visible tool exposure. Treat plugin registration and allowlisting as prerequisites, not proof that the gateway exposes the tools. Record gateway exposure as unknown when its discovery probe is unsupported, empty, or times out; prove it with a successful gateway-visible invocation before claiming end-to-end availability. Identify the effective worker user and group from runtime service metadata. Resolve the principal from the active service instead of inferring it from unit names or documentation. For a temporary validation harness, make the directory traversable and files readable or executable by that principal, then run a harmless identity or version check under it before interpreting denied operations as policy blocks. Distinguish harness launch failures from genuine policy rejections. Compare deployed artifacts with the intended build when both are available. Complete when each runtime layer has separate evidence or an explicit unknown, and artifact identity, effective principal, harness reachability, and policy-check provenance are recorded.

2. Inspect the migrated binding store structurally. Record its schema version, binding count, connector assignment, and whether every preexisting entry was preserved without printing account identifiers or credential material. Complete when migration preservation is established.

3. Exercise one minimal read-only provider operation for each authorized binding and action family. Use deliberately bounded or non-matching inputs where supported. Capture each result independently so one failure cannot abort the matrix. Complete when every attempted binding/action pair has an individual outcome.

4. Classify failures by boundary. Treat authorization success followed by provider-operation failure as binding-specific until a working binding on the same deployed connector disproves a rollout-wide fault. Correlate only sanitized error codes and audit metadata. Complete when each failure is assigned to authorization, connector dispatch, credential/provider execution, or remains explicitly unknown.

5. Verify tenant isolation with a cross-subject request that targets another binding. Expect denial before provider access and confirm the system does not fall back to a working account. Complete when the cross-subject attempt is denied or the rollout is blocked as unsafe.

6. Verify connector isolation with a request whose connector identity does not match an available operation or binding. Expect denial and confirm there is no connector fallback. Complete when the cross-connector attempt is denied or the rollout is blocked as unsafe.

7. Preserve stale or failing bindings unless the owner authorized a state change. Report reconnection as the recovery when evidence identifies an unusable grant. Complete when no destructive credential or binding change occurred implicitly.

8. Report the smallest proof set: runtime health, artifact identity, migration preservation, per-binding read-only outcomes, both isolation results, backup or recovery location when one exists, and any remaining reconnect requirement. Complete when every rollout claim maps to observed evidence.
