![Tidebroker banner](https://github.com/user-attachments/assets/32da87d1-3f7a-4314-a132-ec5de5e2b00a)

# Tidebroker

[![Release](https://img.shields.io/github/v/release/Solvelyllc/Tidebroker)](https://github.com/Solvelyllc/Tidebroker/releases/latest)
[![CI](https://github.com/Solvelyllc/Tidebroker/actions/workflows/ci.yml/badge.svg)](https://github.com/Solvelyllc/Tidebroker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Solvelyllc/Tidebroker/actions/workflows/codeql.yml/badge.svg)](https://github.com/Solvelyllc/Tidebroker/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/Solvelyllc/Tidebroker)](LICENSE)

Tidebroker connects OpenClaw to user-owned provider accounts without exposing credentials to the model. It binds every operation to the trusted requester, workspace, connector, and account. If Tidebroker cannot resolve one exact binding, it denies the operation.

Use this README to install Tidebroker, configure its isolated worker, connect Google Workspace, and verify the deployment. See the linked reference documents for production hardening and protocol details.

## What Tidebroker does

Tidebroker separates agent tools from provider credentials. OpenClaw receives bounded tools, while an isolated worker stores encrypted OAuth credentials and executes reviewed provider operations.

The current release supports these Google Workspace operations:

| Service | Available operations | Write policy |
| --- | --- | --- |
| Google Calendar | List, create, update, and delete events | Each mutation requires one exact approval |
| Gmail | Search, read, and send plain-text messages | Each send requires one exact approval |
| Google Drive | List opaque file IDs and MIME types | Read-only |
| Google Docs | Read opaque document metadata | Read-only |
| Google Sheets | Read an opaque spreadsheet ID | Read-only |

Tidebroker can authorize additional services exposed by an installed `gogcli` release. Authorization does not make those services callable. A service needs a reviewed Tidebroker adapter, strict output projection, policy, and tests before OpenClaw can use it.

## Requirements

Prepare these components before installation:

- OpenClaw `2026.8.1` or newer
- Node.js supported by your OpenClaw release
- A dedicated operating-system account for `tidebroker-worker`
- A Google OAuth client with the required redirect URI and application programming interfaces (APIs) enabled
- Owner-only files for encryption, grant authentication, and OAuth client configuration
- Linux when you use the external `gogcli` backend

The production worker runs outside the OpenClaw Gateway. Do not run it inside the model process or store provider credentials in OpenClaw configuration.

## Install the plugin and worker

Tidebroker `v1.1.3` is published as an attested GitHub release artifact. Download the package and checksum file from the release, verify the package, then install it through OpenClaw's managed package path.

```bash
release_base="https://github.com/Solvelyllc/Tidebroker/releases/download"
release_url="$release_base/v1.1.3"
curl -LO "$release_url/solvely-tidebroker-1.1.3.tgz"
curl -LO "$release_url/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS

openclaw plugins install npm-pack:./solvely-tidebroker-1.1.3.tgz
openclaw plugins enable tidebroker
openclaw plugins inspect tidebroker --runtime --json
```

Install the worker executable from the same verified artifact. Choose an npm prefix that places `tidebroker-worker` at the path used by your service unit.

```bash
sudo npm install --global ./solvely-tidebroker-1.1.3.tgz
command -v tidebroker-worker
```

The release also includes a Software Package Data Exchange (SPDX) software bill of materials, provenance, and GitHub attestations. Review them on the [v1.1.3 release page](https://github.com/Solvelyllc/Tidebroker/releases/tag/v1.1.3).

## Configure the worker

The worker owns credentials, OAuth state, account bindings, replay state, outcomes, and its audit journal. Configure it with owner-controlled paths and opaque deployment identifiers.

1. Create a dedicated worker account and private state directories
2. Create separate 32-byte encryption and grant-authentication keys with the host's secret manager
3. Store the Google OAuth client ID and secret in owner-only files
4. Create `/etc/tidebroker/worker.json` from the [worker configuration example](docs/DEPLOYMENT.md#worker-configuration)
5. Install the `tidebroker-worker` service from the [systemd example](docs/DEPLOYMENT.md#worker-service)
6. Start the worker and validate its socket

Run the worker check after provisioning:

```bash
tidebroker-worker --check /etc/tidebroker/worker.json
systemctl enable --now tidebroker-worker
systemctl status tidebroker-worker
```

Use a mode-`0600` owner socket or a mode-`0660` group socket. If you use group access, limit membership to the worker and OpenClaw Gateway service accounts.

## Choose a Google backend

Select one backend in the worker configuration. Tidebroker never switches backends automatically.

### Use direct Google APIs

Choose `direct` when you need Calendar and Gmail without an external command-line interface (CLI):

```json
{
  "googleExecution": {
    "backend": "direct",
    "timeoutMs": 30000,
    "maxResponseBytes": 1048576
  }
}
```

Direct mode uses fixed Google origins and paths. It disables redirects and returns bounded projections instead of raw provider responses.

### Use external gogcli

Choose `gog` when you need the reviewed Drive, Docs, and Sheets adapters or the broader Google authorization catalog. Tidebroker does not bundle `gogcli` code or binaries.

1. Review [`gogcli`](https://gogcli.sh/) and its [source repository](https://github.com/openclaw/gogcli)
2. Build a restricted binary with [`scripts/gog-safety-profile.yaml`](scripts/gog-safety-profile.yaml)
3. Install the binary in an owner-controlled, non-writable path
4. Record its lowercase SHA-256 digest in the worker configuration
5. Treat every `gogcli` upgrade as a compatibility-gated deployment change

Configure the reviewed binary:

```json
{
  "googleExecution": {
    "backend": "gog",
    "executablePath": "/usr/local/lib/tidebroker/gog-safe",
    "executableSha256": "reviewed_lowercase_sha256_here",
    "configRoot": "/var/lib/tidebroker-worker/gog",
    "httpsProxy": "http://127.0.0.1:3128",
    "timeoutMs": 30000,
    "maxOutputBytes": 1048576
  }
}
```

The current adapter contract targets `gogcli v0.37.0`. Tidebroker rejects an unexpected binary digest, command, service, or response shape.

## Configure OpenClaw

OpenClaw needs the worker socket, a copy of the grant-authentication key, trusted identity mappings, and an agent-to-workspace mapping. It does not receive provider tokens or encryption keys.

Add the Tidebroker plugin settings from the [OpenClaw activation example](docs/DEPLOYMENT.md#openclaw-activation), then allow the tools you want the agent to use. Keep `workerAccountDiscovery` enabled unless your deployment manages non-secret account projections itself.

Restart the Gateway after changing plugin configuration:

```bash
openclaw plugins inspect tidebroker --runtime --json
openclaw gateway restart
openclaw gateway status --deep --require-rpc
```

Tidebroker exposes optional tools only during a trusted interactive turn with an exact subject, workspace, connector, and account binding. Background jobs, public sessions, missing identities, and ambiguous bindings receive no usable provider tool.

## Connect Google Workspace

Connect each person separately. Never share one Tidebroker subject, Google binding, or approval identity between collaborators.

### Connect from OpenClaw WebUI

1. Ask OpenClaw to connect Google Workspace
2. Select the services to authorize in the inline picker
3. Open the worker-owned loopback URL
4. Complete Google consent in the browser
5. Close the page after Tidebroker confirms encrypted credential custody

The picker controls OAuth scopes. Reconnect the account to add or remove authorized services. Tidebroker does not silently broaden an existing grant.

### Connect from the host

Create an owner-only request with the opaque subject, workspace, and trusted membership path. Then start the same one-shot browser flow from the worker:

```bash
tidebroker-worker --connect-google \
  /etc/tidebroker/worker.json \
  /etc/tidebroker/connect-google.json
```

Open only the loopback URL printed by the worker. Never paste an authorization code, token, client secret, or credential into chat or a shell argument.

## Verify the deployment

Verify the worker, plugin, identity binding, provider reads, and approval path before regular use.

1. Confirm `tidebroker-worker --check` succeeds
2. Confirm `openclaw plugins inspect tidebroker --runtime --json` lists the expected tools
3. Run a Calendar list from a trusted user turn
4. Run a Gmail search from the same user turn
5. Run Drive, Docs, and Sheets metadata reads when you use the `gog` backend
6. Confirm an unmapped user receives no Tidebroker tools
7. Confirm a write displays the exact approval details before execution

Read-only calls must return bounded projections. Provider text is marked as untrusted content. A failed account lookup must return an error instead of using another account.

## Revoke a connection

Create an owner-only revocation request with the worker-private credential handle, then run:

```bash
tidebroker-worker --revoke \
  /etc/tidebroker/worker.json \
  /etc/tidebroker/revoke-google.json
```

Local revocation always increments the credential generation and disables discovery. If Google cannot confirm provider revocation, the old local credential remains unusable.

## Understand the security boundary

Tidebroker protects against accidental or model-directed cross-account selection. It does not protect against a malicious host administrator or a modified OpenClaw runtime.

The deployment relies on these controls:

- Exact requester, workspace, connector, and account resolution
- Encrypted credentials in an isolated worker
- Short-lived, single-use grants with replay protection
- Exact, single-use approvals for mutations
- Fixed command and network allowlists
- Strict input and output schemas
- Durable audit, intent, and outcome journals
- Fail-closed behavior when identity, storage, policy, or provider state is uncertain

For production hardening, read:

- [Security architecture](docs/SECURITY-ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Production activation](docs/DEPLOYMENT.md)
- [Worker protocol](docs/WORKER-PROTOCOL.md)
- [Audit event contract](docs/AUDIT-EVENTS.md)
- [Connector capability contract](docs/CONNECTOR-CAPABILITIES.md)

## Add another provider

Tidebroker core is provider-neutral. A connector owns its provider-specific behavior and must define:

- Credential and authorization strategy
- Capability and action identifiers
- Required permissions
- Input and output schemas
- Mutation approval policy
- Bounded projections
- Negative isolation and shape-drift tests

Start with the [connector capability contract](docs/CONNECTOR-CAPABILITIES.md). Do not add provider branches to broker core or expose a generic shell or HTTP escape hatch.

## Develop Tidebroker

Install dependencies and run the complete validation suite:

```bash
npm install
npm run check
```

Run individual checks while developing:

```bash
npm test
npm run build
npm run plugin:validate
npm pack --dry-run
```

`npm pack` runs the build, package validation, shape self-tests, and test suite through `prepack`. Tests do not connect live credentials or publish artifacts.

## Release a version

Public releases require exact-commit evidence, protected CI and CodeQL checks, a packed-artifact rehearsal, checksums, an SPDX software bill of materials, and provenance attestations. Follow [the public release procedure](docs/PUBLIC-RELEASE.md).

## License

Tidebroker is licensed under [Apache-2.0](LICENSE).
