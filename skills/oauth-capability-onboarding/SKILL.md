---
name: "oauth-capability-onboarding"
description: "Implement capability-aware OAuth onboarding with least-scope mapping, closed custody allowlists, and end-to-end picker verification."
---

# OAuth Capability Onboarding

Use this procedure when an OAuth connection flow lets a user select provider capabilities.

1. Define a provider-neutral capability descriptor in broker core, and keep provider scopes, authorization kinds, canonicalization, and action mappings in the provider adapter. Confirm broker core contains no provider-specific capability rules.

2. Classify each reviewed capability as executable or authorization-only. Give executable capabilities an explicit closed action set with read or approval-required policy metadata; give authorization-only capabilities no actions. Confirm credential possession alone cannot expose an unreviewed action.

3. Encode implication rules before combining selections. Let a stronger capability include its required weaker actions while replacing redundant weaker scopes where the provider scope already covers them. Confirm the resolved scope set is minimal and the action set remains complete.

4. Keep the credential custodian's accepted-scope allowlist as the closed superset of every reviewed scope. Request only the resolved subset for each connection. When the provider returns canonical or associated identity scopes, make the proven scopes explicit in both the authorization request and the allowlist instead of weakening overgrant rejection. Confirm every returned scope was disclosed in the request and accepted by the closed allowlist.

5. Reject empty and unknown selections before authorization begins. Confirm invalid selections produce the flow's deterministic validation error.

6. Persist `connectorId` and the resolved allowed-action set with each credential binding, and include `connectorId` in actor/workspace uniqueness and lookup keys. Require reconnection to expand or reduce capabilities. Confirm reconnect changes the credential generation so earlier grants cannot regain validity.

7. When introducing connector-scoped bindings, inspect deployed binding metadata without identities, accounts, scopes, or credentials: record the schema version, entry count, and whether connector identifiers are present. Read legacy records only through an explicit provider-declared connector mapping, validate their actions against that connector's closed binding set, and write the current schema through the normal binding store. Confirm migrated records carry the intended connector and invalid or ambiguous legacy records fail closed.

6. Test read-only, stronger-capability, independent-capability, empty, and unknown selections. Assert both included and excluded scopes and the exact allowed actions for each branch. Confirm the focused tests pass.

7. Document the default choices, optional capabilities, minimum-scope behavior, and reconnection rule. State that provider features outside the reviewed adapter, projection, policy, and tests are not selectable. Confirm implementation and operator documentation agree.

8. Validate loopback form submissions with the one-time CSRF proof and browser request metadata. Accept an absent or `null` Origin only when Fetch Metadata does not classify the request as cross-site; require an explicit Origin to match the exact loopback endpoint. Confirm tests cover valid loopback, absent Origin, `null` Origin, cross-site metadata, foreign origins, and wrong ports.

9. Run the repository's full validation suite, then start the built onboarding worker through the deployed execution path. Fetch the loopback page and verify the expected capability controls, continuation action, no-store caching, content-security policy, and frame denial. Confirm both package validation and the live picker checks pass.

10. Check the request session's effective tool surface before invoking actor-scoped onboarding. Treat configuration allowlisting and source registration as prerequisites, not proof of exposure. If the tool is absent, verify enabled deployment configuration and trusted host actor context, then construct the built onboarding tool through its exported factory with that validated configuration and host context. Execute it with the reviewed capability selection and confirm it returns the expected authorization URL, expiry, and selected capabilities without exposing credentials.
