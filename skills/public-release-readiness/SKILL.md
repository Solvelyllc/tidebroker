---
name: "public-release-readiness"
description: "Assess public-launch readiness by verifying active, pending, finalization, and channel-specific release gates."
---

# Public Release Readiness

Use this procedure to assess whether a software release is ready for public launch.

1. Name the decision scope: private checkpoint, general public release, or publication through a specific channel. Record one explicit target scope.

2. Inspect current repository state, release-gate scripts, CI workflows, remote security controls, and existing release assets. Record evidence for each claimed state.

3. Separate findings into four classes:
   - **Active blockers:** controls or checks that currently fail or are disabled.
   - **Pending gates:** required tests or evidence not yet completed.
   - **Finalization requirements:** signing, artifacts, checksums, SBOM, provenance, or attestations required for the final release.
   - **Channel-specific requirements:** safeguards required only when publishing through that channel.
   Confirm every requirement appears in exactly one class for the target scope.

4. Treat a successful private checkpoint as distinct from public-launch readiness. State both conclusions when the checkpoint is valid but public gates remain.

5. Treat valid provider output as execution evidence, not schema approval. Require every advertised capability to match a reviewed, version-pinned response-shape contract; fail closed on unreviewed shapes, missing or extra fields, wrong types or nesting, and declared size-bound violations. Exercise negative fixtures offline, then require fresh live matrix evidence in the public-release gate. Complete when offline contract tests pass and commit-bound live evidence covers every advertised capability.

6. Order next actions by dependency: unblock unavailable controls first, run their checks, produce commit-bound operational evidence, then build and sign final artifacts. When SSH signing is required, compare the configured signing key, paired public key, and tracked allowlist fingerprints before creating the signed commit or tag; after signing, verify that the signature resolves to the intended allowlist principal. Identify the first executable action and any owner decision it requires, and record matching preflight fingerprints plus a valid principal-bound signature.

7. Rehearse fail-closed artifact generation from a disposable clean checkout of the exact candidate commit. Inspect the builder to identify required repository state before retrying; when it requires the final version tag, create an unpushed local tag only inside the disposable checkout. Verify the generated artifacts and checksums, label the result as rehearsal rather than signing evidence, and remove the checkout. Confirm no rehearsal tag or artifact was published.

8. Prove branch-protection gates are satisfiable through the intended promotion path before enforcing them. Ensure every required check triggers on the candidate ref, validate the exact candidate commit there, and record a promotion path that preserves signature and status-check enforcement.

9. Re-run the project’s release check and inspect remote checks or assets after changes. Report ready only when all target-scope gates have current evidence and no active blocker remains.
