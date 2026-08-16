# Tidebroker

An OpenClaw plugin foundation for binding CLI, MCP, and HTTP connector execution to the human who initiated the current turn.

The central invariant is simple:

```text
trusted requester + selected workspace + connector -> one exact account binding
```

There is no global, last-used, other-user, or ambient credential fallback.

## Status

Version 1.1 adds selectable direct-Google and external-`gog` execution while keeping the installed plugin
fail closed until a deployment supplies its trusted stores, worker, and host workspace
adapter. It currently provides:

- host-context-only identities mapped exactly to random deployment-issued subjects;
- immutable trusted selected-workspace bindings with repeated membership checks;
- exact, fail-closed workspace and account policy resolution;
- human and explicit service-principal namespaces;
- a requester-scoped MCP endpoint/header validation adapter for connector implementations;
- an isolated, shell-free CLI execution adapter;
- authenticated short-lived, action- and generation-bound worker grants with replay protection;
- a mode-`0600` Unix-socket worker protocol with bounded frames, timeouts, and concurrency;
- optional dedicated-group `0660` socket access for separate Gateway/worker OS identities;
- a runnable `tidebroker-worker` service with secure key files, health checks,
  graceful shutdown, and conservative stale-socket recovery;
- durable private-file adapters with atomic writes and restart-safe OAuth/replay/outcome state;
- encrypted OAuth custody, single-use OAuth state, PKCE, signed OIDC validation, and revocation;
- a one-shot loopback-only Google connection flow whose authorization response uses POST;
- worker-private account discovery authenticated by the same short-lived grants as execution;
- fixed Google Calendar and Gmail operations executed either directly over bounded Google APIs or by an administrator-provisioned `gog` binary;
- bounded Gmail search/read that marks provider content untrusted, plus exact-approval plain-text sending;
- closed-schema audit events, sink readiness, and invalidation hooks;
- threat-model and security-architecture documentation;
- an optional `tidebroker_status` diagnostic tool.

The credential worker must be deployed out of process under a separate OS/container
boundary. The plugin never activates Google access without deployment-owned configuration,
an exact trusted actor/workspace binding, and a connected worker-private account.

## Target architecture

```text
OpenClaw trusted requester context
                |
                v
            Tidebroker
       | identity + policy
       | connector resolution
       | closed-schema audit
       +------------------------+
       |                        |
       v                        v
requester-scoped MCP   mode-0600 Unix socket
       |                        |
       +------------+-----------+
                    v
          isolated credential worker
          + encrypted credentials
          + durable replay/outcomes/audit
```

Public SDK modules are available from `@solvely/tidebroker/sdk`:

- `core`: identity, opaque subject mapping, trusted run binding, policy, and connector contracts;
- `mcp`: requester-scoped MCP resolver adapter;
- `cli`: safe CLI binding, allowlist, and execution primitives;
- `credentials`: encrypted records, OAuth custody, and revocation;
- `durable`: private atomic credential, metadata, subject, membership, OAuth,
  replay, mutation-outcome, and audit adapters;
- `worker`: authenticated grants, replay prevention, and isolated dispatch;
- `connectors`: fixed Google Calendar and Gmail operations with worker-owned backend selection;
- `audit`: closed-schema events and sink contracts. Callers must
  pass registry-issued opaque identifiers, never secrets or provider data.

## Requester-scoped MCP

OpenClaw must statically know the MCP server name and tool schema. Connector implementations can use `createRequesterScopedMcpResolver` to bind that server's transport to a trusted requester for each run.

The foundation deliberately does **not** register a raw identity-header loopback route. A production connector must first resolve the full trusted requester tuple to a deployment-owned opaque subject, enforce exact workspace/account policy, and mint an authenticated short-lived capability for its credential worker. Plain actor headers are forgeable by other local processes and are not an acceptable authorization boundary.

## CLI security boundary

The CLI adapter:

- executes exact absolute binaries with `shell: false`;
- performs no `PATH` lookup;
- inherits no process environment;
- provides no stdin;
- rejects credential-bearing flags;
- validates actor config directories using real paths and root containment;
- binds each config directory to the exact authorized actor/workspace/account context;
- supports operation and flag allowlists;
- enforces timeout, cancellation, and combined output limits;
- terminates the full process group on POSIX (Windows needs a Job Object or container
  for an equivalent descendant boundary);
- returns deterministic errors without argv, environment, or underlying causes.

Connector authors must supply a provider-aware output sanitizer. Credentials belong in the actor-specific worker's protected store, never in argv or caller-provided environment values.

## Google execution backends

The worker administrator explicitly selects exactly one Google Workspace backend.
There is no automatic fallback and the backend is never model-visible.

- `direct` uses fixed `https://www.googleapis.com` paths, header-only access tokens,
  redirects disabled, bounded JSON, and strict Calendar/Gmail projections. Gmail
  HTML, attachments, raw MIME, and arbitrary headers are never returned.
- `gog` invokes an externally provisioned, owner/mode/SHA-256-verified binary with
  a private state root, closed child environment, exact command allowlists,
  minimal projections, strict closed JSON schemas, and Gmail bodies over stdin.

Tidebroker does **not** bundle the `gog` binary or its source. The included
`scripts/gog-safety-profile.yaml` is only a reproducible recipe for administrators
who choose that backend. Both modes retain identical actor/account isolation,
short-lived grants, write approvals, audit, replay protection, and revocation.
In direct mode, the Calendar `today` filter uses the current UTC calendar day;
deployments needing a local-day policy should translate that intent before invoking
the fixed operation rather than accepting a model-supplied time zone.

OAuth connection is a one-shot worker-owned loopback UI. The Google response uses
`form_post`, so authorization codes are received in a bounded POST body; code and
token responses remain inside the credential worker and are never returned to chat,
argv, logs, audit events, URLs, or tool results. See the production activation guide.

`ActorScopedGoogleCalendarRuntime` wires trusted host context to the broker and
Unix worker client. Its model-visible input accepts only `today` and
`maxResults`; actor, workspace, account, endpoint, and credential selectors are
rejected.

## Security documentation

- [Security architecture](docs/SECURITY-ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Audit event contract](docs/AUDIT-EVENTS.md)
- [Worker deployment protocol](docs/WORKER-PROTOCOL.md)
- [Production activation](docs/DEPLOYMENT.md)

OpenClaw plugins execute trusted code inside the Gateway. This project prevents accidental or model-directed cross-account selection; it does not make a shared Gateway safe against a malicious host administrator or modified plugin runtime. Strong credential isolation requires an out-of-process worker with its own OS/container boundary.

## Development

Requirements:

- Node.js supported by the target OpenClaw release;
- OpenClaw `>=2026.8.1`;
- npm.

When developing against a host build newer than the public npm package, link that exact host package without saving it:

```bash
npm install
npm link --no-save openclaw
npm run check
```

Normal verification:

```bash
npm test
npm run build
npm run plugin:validate
npm pack --dry-run
```

`npm pack` runs the full build, validation, and test suite through `prepack`, so a
clean checkout cannot produce a package missing its runtime files.

Before a public ClawHub release, push the exact release commit
to a public source repository, test the packed artifact through OpenClaw's
managed `npm-pack:` install path, and produce owner-only release evidence for OS
isolation, a real-provider smoke test, and MCP schema quarantine. `npm publish`
is blocked unless `TIDEBROKER_RELEASE_EVIDENCE_PATH` names an owner-only evidence
file bound to the exact `HEAD`; validate it with `npm run release:check`. Then run:

```bash
clawhub package validate . --openclaw /path/to/openclaw
clawhub package publish . \
  --family code-plugin \
  --owner solvely \
  --source-repo <owner>/<repository> \
  --source-commit "$(git rev-parse HEAD)" \
  --dry-run
```

The `@solvely` npm scope must match the selected ClawHub owner. The release
artifact is controlled by `package.json#files`; local OpenClaw workspace files,
runtime state, credentials, tests, and TypeScript sources are excluded. No
publication or live credential connection is performed by this repository's
test suite.
