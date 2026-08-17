---
name: "provider-mutation-outcome-safety"
description: "Implement provider mutations with durable outcomes, call-boundary tracking, and safe retry classification."
---

# Provider Mutation Outcome Safety

Use this procedure when an operation can mutate an external provider and a timeout or process failure may hide whether the mutation completed.

1. Key each mutation with a stable request identifier and persist its intent before execution. Complete when the intent exists before any provider call.
2. Reject or resolve duplicate request identifiers from the stored outcome without invoking the provider again. Complete when a duplicate-execution test observes no second provider call.
3. Refresh or resolve credentials, then recheck their active generation immediately before provider I/O. Complete when a revocation injected after refresh prevents the provider call.
4. Mark the provider-call boundary immediately before invoking the external subprocess or network request. Complete when pre-call and post-call failures are distinguishable in tests.
5. Persist `succeeded` only after the provider returns success. Persist `failed` for errors proven to occur before provider I/O, and persist `unknown` for every error after provider I/O begins. Complete when each branch records the expected durable status.
6. Return unknown outcomes as non-retriable so automatic retries cannot duplicate an external write. Complete when a post-call timeout produces an unknown, non-retriable result.
7. Treat outcome-journal or post-success audit failures as unknown unless durable state proves the final provider result. Complete when storage-failure tests fail closed without re-executing the mutation.
8. Run the repository build and focused mutation tests, then run the full validation gate. Complete when type checking, boundary tests, duplicate tests, and the full suite pass.
