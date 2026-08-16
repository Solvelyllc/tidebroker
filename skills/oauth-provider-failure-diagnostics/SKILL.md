---
name: "oauth-provider-failure-diagnostics"
description: "Diagnose generic OAuth connector failures by isolating refresh and provider stages without exposing credential material."
---

# OAuth Provider Failure Diagnostics

Use this procedure when a credential worker accepts a grant but reports only a generic provider-operation failure.

1. Inspect structured audit events first. Separate grant denial, credential redemption, and provider execution by outcome and reason code. Complete when the failure boundary is identified without reading credential payloads.

2. Verify provider reachability without authentication. Resolve the provider hosts and make unauthenticated requests that report status only. Treat the response as network evidence, not authorization evidence. Complete when DNS and HTTP reachability are confirmed or ruled out.

3. Read the worker operation and credential-store implementation. Identify each outbound provider stage, the credential material shape, and the point where detailed errors become generic. Complete when the diagnostic can mirror the real execution path.

4. Run a worker-local diagnostic that uses the existing secure credential path and performs each provider stage in order. Emit only the failing stage, HTTP status, and a strictly validated provider error class. Keep tokens, client values, account identity, authorization headers, and response bodies out of output and transcripts. Complete when one stage succeeds and the next returns a bounded diagnostic result, or all stages succeed.

5. Apply the provider-specific recovery only after the failing stage is proven. For Google Calendar `accessNotConfigured`, follow [references/google-calendar.md](references/google-calendar.md). Complete when the recovery target is tied to the diagnosed OAuth project rather than guessed configuration.

6. Re-run the original connector operation after recovery. Verify a successful worker result and corresponding audit outcome. Complete when the end-to-end path succeeds through the normal worker boundary.
