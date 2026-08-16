---
name: "google-api-admin-readiness"
description: "Grant or verify Google API-enablement access with least privilege and end-to-end deployment checks."
---

# Google API Admin Readiness

Use this procedure when a deployment must enable additional Google APIs through an existing OAuth connector.

1. Inspect the deployed connector, worker configuration, and tool registration. Confirm the operation targets a configured project rather than accepting a caller-supplied project ID.

2. Trace the complete authorization path: requested OAuth scopes, stored credential type, project IAM permission, and per-call write approval. Confirm each layer independently; a broad OAuth scope does not prove project IAM authority.

3. Choose the narrowest project role that permits service enablement. Keep billing, IAM administration, project deletion, and cross-project access outside the role, and record the resulting project boundary.

4. Reuse the existing OAuth client and credential when their scope and IAM permissions already satisfy the operation. Add a new credential only when the verified authorization path has a specific unmet requirement.

5. Verify the mutation guardrails in code and tests. Confirm strict service-name validation, bounded request size, exact-project routing, explicit approval consumption, and generic credential-safe error reporting.

6. Validate the deployed configuration and plugin, then resolve the live worker executable to its exact installed package before running maintenance code. Confirm the expected plugin version is loaded, maintenance imports come from that deployed package, and both runtime services report healthy.

7. After an OAuth reconnection, compare the current account binding with the credential metadata inventory. Locally invalidate any superseded active record through the deployed credential-store API when the provider grant must remain valid; confirm the intended binding is active and every superseded record is revoked.

8. Exercise readiness with a credential refresh and a non-secret inspection or explicitly approved API-enablement call. Confirm the active credential works for the fixed project without exposing account identity, tokens, or credential material.

9. Report the effective capability and exclusions separately. Confirm the operator can tell what may be enabled, which approval is required, and which administrative powers remain unavailable.
