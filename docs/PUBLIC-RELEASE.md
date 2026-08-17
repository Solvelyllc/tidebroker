# Public release procedure

Tidebroker's source repository is public. A passing source test suite and public
visibility are package evidence, not public-launch evidence.

## 1. Repository security

1. Keep the repository variable `TIDEBROKER_CODEQL_ENABLED=true`.
2. Run the `CodeQL` workflow and resolve every alert before release.
3. Require the CI and CodeQL checks on `main`.
4. Confirm both checks also run on the exact `release/**` candidate commit before
   fast-forward promotion to `main`.

## 2. Operational evidence

Create a private directory owned by the release operator with mode `0700`. All
evidence files must be newly created, mode `0600`, recent, and bound to the exact
release commit.

### OS isolation

The collector checks the live systemd worker, separate non-root worker identity,
private credential tree, systemd hardening, and an explicit cgroup IP deny/allow
policy. It refuses to create evidence unless every check passes.

```bash
TIDEBROKER_OS_EVIDENCE_PATH=/secure/release/os.json \
TIDEBROKER_WORKER_CONFIG_PATH=/etc/tidebroker/worker.json \
TIDEBROKER_GATEWAY_USER=openclaw \
npm run evidence:os
```

`IPAddressDeny=any` plus a reviewed non-empty `IPAddressAllow` policy must be
visible in `systemctl show` for the worker. Code-level URL allowlists do not prove
OS egress isolation.

### MCP quarantine

```bash
TIDEBROKER_MCP_EVIDENCE_PATH=/secure/release/mcp.json npm run evidence:mcp
```

This executes exact-schema, schema-drift, and unknown-tool cases against the
built quarantine implementation. Schema or privilege drift never updates the
deployment allowlist automatically.

### Real-provider smoke test

Using a dedicated test account and the normal OpenClaw approval UI, exercise:

- one bounded Calendar read;
- one bounded Gmail read;
- the complete executable Google capability smoke matrix, with every command in
  the production `gog-safety-profile.yaml` matching the strict parser shipped by
  the exact deployed Tidebroker commit;
- one reversible approved write, followed by cleanup;
- one unmapped requester, which must receive no connector capability.

Authorization-only OAuth services are not execution claims and receive zero agent
actions. They are covered by catalog/scope tests, not provider response-shape
evidence. The executable-capability status must remain failed while any production
command is unavailable, resource-dependent coverage is missing, or projected JSON
violates its strict parser. Run the content-free executable smoke as the isolated
worker identity before recording evidence:

```bash
TIDEBROKER_WORKER_CONFIG_PATH=/etc/tidebroker/worker.json \
npm run smoke:google-executable
```

Record only the five statuses in an owner-only copy of
`docs/release-evidence/real-provider-results.example.json`. Never record provider
content, account names, email addresses, credential handles, or tokens.

```bash
TIDEBROKER_REAL_PROVIDER_RESULTS_PATH=/secure/release/provider-results.json \
TIDEBROKER_REAL_PROVIDER_EVIDENCE_PATH=/secure/release/provider.json \
npm run evidence:provider
```

### Summary and gate

```bash
TIDEBROKER_OS_EVIDENCE_PATH=/secure/release/os.json \
TIDEBROKER_REAL_PROVIDER_EVIDENCE_PATH=/secure/release/provider.json \
TIDEBROKER_MCP_EVIDENCE_PATH=/secure/release/mcp.json \
TIDEBROKER_RELEASE_EVIDENCE_PATH=/secure/release/summary.json \
npm run evidence:summary

TIDEBROKER_RELEASE_EVIDENCE_PATH=/secure/release/summary.json \
npm run release:check
```

## 3. Keyless trusted release

1. Merge the release candidate through protected `main` after the required CI
   and CodeQL checks pass. The release workflow refuses any other ref or a
   checkout that differs from current `origin/main`.
2. Add the completed, content-free evidence JSON as base64 secrets in the
   `production-release` environment named
   `TIDEBROKER_OS_EVIDENCE_B64`, `TIDEBROKER_PROVIDER_EVIDENCE_B64`, and
   `TIDEBROKER_MCP_EVIDENCE_B64`. Never store provider content or credentials.
3. Set the repository variable `TIDEBROKER_RELEASE_AUTOMATION_ENABLED=true` only
   after all three evidence files are bound to the exact release commit.
4. Dispatch `Release artifacts` from `main` with the version from `package.json`
   as `vX.Y.Z`.

The workflow reruns source/package/audit checks, enforces deployment evidence,
creates the annotated version tag, and produces the npm tarball, SPDX SBOM,
SHA-256 checksums, and release manifest. GitHub Actions uses OIDC-backed Sigstore
attestations for both build provenance and the package SBOM and attaches the
verification bundles and their checksums. It uploads the verified asset set to
a draft and then publishes it; repository release immutability locks the
resulting tag and assets and creates GitHub's separate release attestation. No
long-lived release-signing key is used.

## 4. Public-visibility review

Before changing visibility, inspect both the current tree and the full Git
history. At minimum:

- run TruffleHog with verified-secret detection over all refs;
- inspect commit authors and messages for personal identity disclosure;
- search every revision for email addresses, hostnames, absolute home paths,
  deployment IDs, account handles, and production configuration;
- inspect the exact npm tarball and SBOM;
- confirm issues, pull requests, Actions logs/artifacts, tags, and releases are
  safe to expose.

If historical identity or operational data is not intended to be public, create
a new sanitized public repository. Do not rewrite or force-push the private
repository merely to conceal already-published immutable release metadata.
