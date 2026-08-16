# Public release procedure

Tidebroker remains private until every item below is complete. A passing source
test suite is package evidence, not public-launch evidence.

## 1. Repository security

1. Enable GitHub Code Security for the private repository, or make the repository
   public only after the privacy and operational gates below are complete.
2. Set the repository variable `TIDEBROKER_CODEQL_ENABLED=true`.
3. Run the `CodeQL` workflow and resolve every alert before release.
4. Require the CI and CodeQL checks on the default branch.

The checked-in CodeQL workflow is deliberately inert until the variable is set,
because GitHub rejects private-repository uploads when Code Security is disabled.

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
- one reversible approved write, followed by cleanup;
- one unmapped requester, which must receive no connector capability.

Record only the four statuses in an owner-only copy of
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

## 3. Signed source and artifacts

1. Add each approved release signer's SSH public key to the tracked
   `.github/release-allowed-signers` file using Git's allowed-signers format.
2. Sign the final release commit and annotated tag with that key.
3. Configure a dedicated self-hosted runner labeled `tidebroker-release`. It must
   have read-only access to the completed evidence directory, not provider
   credentials.
4. Set `TIDEBROKER_RELEASE_EVIDENCE_PATH` in the runner environment, protect the
   `production-release` GitHub environment, and set the repository variable
   `TIDEBROKER_RELEASE_AUTOMATION_ENABLED=true`.
5. Dispatch `Release artifacts` for the signed tag.

The workflow verifies the commit and tag signatures, reruns source/package/audit
checks, enforces deployment evidence, and produces the npm tarball, SPDX SBOM,
SHA-256 checksums, release manifest, and GitHub build-provenance attestation.
Download and inspect the workflow artifact before attaching all files to a draft
GitHub release. Publish only after the asset set is complete; immutable releases
cannot be repaired afterward.

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
