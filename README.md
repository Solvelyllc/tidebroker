![Tidebroker banner](https://github.com/user-attachments/assets/32da87d1-3f7a-4314-a132-ec5de5e2b00a)

# Tidebroker

**Approval-gated credential brokerage and actor-scoped connectors for OpenClaw.**

Tidebroker is an OpenClaw plugin foundation that binds CLI, MCP, and HTTP connector
execution to the human who initiated the current turn. It lets an agent use real
provider accounts — calendar, email, and more — without ever giving the model
ambient access to credentials.

The central invariant is simple:

```text
trusted requester + selected workspace + connector -> one exact account binding
```

There is no global, last-used, other-user, or ambient credential fallback.

## Why Tidebroker

Most agent integrations quietly widen access: a shared token, a "default" account,
a credential sitting in an environment variable. Tidebroker is built the other way
around — fail closed, and only ever act as the exact person who asked.

- **Exact identity, every time** — host-context identities map to
  deployment-issued opaque subjects, with immutable trusted workspace bindings and
  repeated membership checks.
- **Encrypted credential custody** — OAuth tokens live in an isolated,
  out-of-process credential worker under its own OS/container boundary. Codes and
  tokens never reach chat, argv, logs, audit events, URLs, or tool results.
- **Short-lived, single-use grants** — workers authenticate with action- and
  generation-bound grants with replay protection; nothing long-lived crosses the
  plugin boundary.
- **Exact approvals for mutations** — writes (like sending email) require explicit
  human approval of the exact action.
- **Audit and revocation** — closed-schema audit events, sink readiness checks,
  and token revocation are first-class, not bolted on.
- **Shell-free execution** — exact absolute binaries, no `PATH` lookup, no
  inherited environment, bounded output, and deterministic errors.

## Current connectors

Tidebroker's security architecture is provider-agnostic. The connectors implemented
today are Google-focused:

- **Gmail** — bounded search/read (provider content marked untrusted) and
  exact-approval plain-text sending.
- **Google Calendar** — fixed read operations with strict projections.

Google access runs through one of two administrator-selected backends — there is no
automatic fallback, and the choice is never model-visible:

- **Direct Google APIs** — fixed `https://www.googleapis.com` paths, header-only
  access tokens, redirects disabled, bounded JSON. Gmail HTML, attachments, raw
  MIME, and arbitrary headers are never returned.
- **External `gog` binary** (Linux only) — an externally provisioned,
  owner/mode/SHA-256-verified binary with a private state root, closed child
  environment, and exact command allowlists. Tidebroker does not bundle `gog`;
  the included `scripts/gog-safety-profile.yaml` is a reproducible recipe for
  administrators who choose this backend.

OAuth connection is a one-shot, worker-owned loopback flow using PKCE, single-use
state, and signed OIDC validation. The plugin never activates Google access without
deployment-owned configuration, an exact trusted actor/workspace binding, and a
connected worker-private account.

## Roadmap

The reusable core — actor/workspace/account isolation, encrypted credential
custody, OAuth state and token lifecycle, short-lived single-use grants, exact
approvals for mutations, audit and revocation, and isolated worker execution — is
deliberately provider-agnostic.

Adding **Microsoft 365, GitHub, Slack, Stripe**, or other OAuth/API providers does
not require rebuilding that security layer. Each new provider needs:

1. a provider adapter;
2. provider-specific scopes and policies;
3. sanitized output projections;
4. operation-specific tests.

Contributions and provider requests are welcome — see the issues page.

## Architecture

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

The credential worker is deployed out of process as a runnable `tidebroker-worker`
service, with secure key files, health checks, graceful shutdown, and a mode-`0600`
Unix-socket protocol with bounded frames, timeouts, and concurrency.

Public SDK modules are available from `@solvely/tidebroker/sdk`:

- `core` — identity, opaque subject mapping, trusted run binding, policy, connector contracts
- `mcp` — requester-scoped MCP resolver adapter
- `cli` — safe CLI binding, allowlist, and execution primitives
- `credentials` — encrypted records, OAuth custody, and revocation
- `durable` — private atomic adapters for credentials, metadata, OAuth, replay, outcomes, audit
- `worker` — authenticated grants, replay prevention, isolated dispatch
- `connectors` — fixed Google Calendar and Gmail operations with worker-owned backend selection
- `audit` — closed-schema events and sink contracts

## Security model

OpenClaw plugins execute trusted code inside the Gateway. Tidebroker prevents
accidental or model-directed cross-account selection; it does not make a shared
Gateway safe against a malicious host administrator or modified plugin runtime.
Strong credential isolation requires the out-of-process worker with its own
OS/container boundary.

Full details:

- [Security architecture](docs/SECURITY-ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Audit event contract](docs/AUDIT-EVENTS.md)
- [Worker deployment protocol](docs/WORKER-PROTOCOL.md)
- [Production activation](docs/DEPLOYMENT.md)

## Development

Requirements: Node.js supported by the target OpenClaw release, OpenClaw
`>=2026.8.1`, and npm.

```bash
npm install
npm run check      # build + package validation + tests
```

```bash
npm test
npm run build
npm run plugin:validate
npm pack --dry-run
```

When developing against a host build newer than the public npm package, link that
exact host package without saving it: `npm link --no-save openclaw`.

`npm pack` runs the full build, validation, and test suite through `prepack`, so a
clean checkout cannot produce a package missing its runtime files. The release
artifact is controlled by `package.json#files`; workspace files, runtime state,
credentials, tests, and TypeScript sources are excluded. No publication or live
credential connection is performed by this repository's test suite.

### Releasing

Before a public release, push the exact release commit to a public source
repository and test the packed artifact through OpenClaw's managed `npm-pack:`
install path. `npm publish` is blocked unless `TIDEBROKER_RELEASE_EVIDENCE_PATH`
names an owner-only evidence file bound to the exact `HEAD`; validate with
`npm run release:check`, then dry-run the ClawHub publish:

```bash
clawhub package validate . --openclaw /path/to/openclaw
clawhub package publish . \
  --family code-plugin \
  --owner solvely \
  --source-repo <owner>/<repository> \
  --source-commit "$(git rev-parse HEAD)" \
  --dry-run
```

## License

[Apache-2.0](LICENSE)
