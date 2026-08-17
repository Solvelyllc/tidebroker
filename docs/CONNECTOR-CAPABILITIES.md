# Connector capability contract

Tidebroker core is provider-neutral. A connector owns provider names, credential
requirements, permissions, action mappings, projections, and provider-specific
authorization behavior. Broker and durable layers operate only on opaque connector,
capability, account, credential, permission, and action identifiers.

## Descriptor

Each selectable capability declares:

- `connectorId` and stable `capabilityId`
- authorization kind: user OAuth, explicit user OAuth, or service account
- exact provider permissions
- availability: `executable` or `authorization-only`
- executable actions, each with mutation status, strict projection, and policy

An executable capability must declare at least one action. A capability with no
reviewed adapter remains authorization-only. This keeps permission onboarding
independent from command exposure without implying that an unimplemented service is
usable by the agent.

The generic resolver rejects empty, duplicate, unknown, cross-connector, and
incompatible authorization selections. Connector adapters may canonicalize provider
permission aliases and add disclosed identity permissions before resolution.

## Account binding

Durable bindings are keyed by `subjectId + workspaceId + connectorId`. The same actor
may therefore connect multiple providers without overwriting another binding. A tool
must select bindings for its own connector; it must never relabel a binding from a
different connector.

Binding file format v2 stores `connectorId`. The worker may migrate a v1 file only
when its deployment-owned connector module supplies the legacy connector identity.
Broker core does not guess a provider.

## Connector conformance

Before an executable capability ships, test:

1. catalog and descriptor validation;
2. exact permission resolution, including aliases and implications;
3. missing permission and overgrant handling;
4. actor, workspace, connector, account, and generation binding;
5. cross-user and cross-connector denial before any provider call;
6. strict input validation and bounded untrusted output projection;
7. read/write separation, approval, audit, and unknown mutation outcomes;
8. revocation and reconnect generation invalidation;
9. provider outage failure with no account or connector fallback;
10. packaged and live onboarding behavior.

Google's external gog catalog is the first adapter for this contract; it is not part
of broker core.
