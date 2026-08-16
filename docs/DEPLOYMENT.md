# Production activation

Version 1.1 provides the worker executable, deployment-gated OpenClaw tools, and a
one-shot Google connection/revocation workflow. Key material must be provisioned
outside chat through owner-controlled files or an OS secret manager.

## Worker configuration

The worker accepts one argument: the path to an owner-only JSON configuration.
The configuration contains paths and opaque identifiers only.

```json
{
  "version": 1,
  "socketPath": "/run/tidebroker/worker.sock",
  "socketAccess": "group",
  "socketGroupId": 2000,
  "recoverStaleSocket": true,
  "credentialRoot": "/var/lib/tidebroker-worker/credentials",
  "metadataRoot": "/var/lib/tidebroker-worker/metadata",
  "replayRoot": "/var/lib/tidebroker-worker/replay",
  "auditRoot": "/var/lib/tidebroker-worker/audit",
  "oauthStateRoot": "/var/lib/tidebroker-worker/oauth-state",
  "accountBindingsPath": "/var/lib/tidebroker-worker/accounts/bindings.json",
  "grant": {
    "issuer": "openclaw-gateway",
    "audience": "tidebroker-worker",
    "keyFile": "/run/tidebroker-worker-secrets/grant-auth.key"
  },
  "encryption": {
    "activeKeyId": "key_2026_08",
    "keys": [
      {
        "id": "key_2026_08",
        "keyFile": "/run/tidebroker-worker-secrets/encryption-2026-08.key"
      }
    ]
  },
  "googleOAuth": {
    "clientIdFile": "/run/tidebroker-worker-secrets/google-client-id",
    "clientSecretFile": "/run/tidebroker-worker-secrets/google-client-secret",
    "redirectUri": "http://127.0.0.1:8765/oauth/google/callback"
  },
  "googleExecution": {
    "backend": "direct",
    "timeoutMs": 30000,
    "maxResponseBytes": 1048576
  },
  "limits": {
    "maxFrameBytes": 1048576,
    "timeoutMs": 30000,
    "maxConcurrent": 16
  }
}
```

Grant and encryption key files are exactly 32 raw bytes, owner-only, regular files, and not
symlink. Provision it with the host's secure credential facility. The Gateway
receives a separate owner-only copy of the grant-authentication key; it never
receives an encryption key or provider credential. Grant and encryption keys
must be distinct files and distinct key material.

The Google client files are owner-only, single-line secure text files. They are
read only by the worker. The configured redirect URI must be the exact loopback
URI registered for the Google OAuth client. Enable the Google Calendar API and
configure the consent screen before connecting. Direct mode needs no Google CLI.
It permits only baked Google API origins and paths, sends access tokens only in the
Authorization header, disables redirects, and strictly bounds/projects responses.

To use an externally installed `gog` instead, replace `googleExecution` with:

```json
{
  "googleExecution": {
    "backend": "gog",
    "executablePath": "/usr/local/lib/tidebroker/gog-safe",
    "configRoot": "/var/lib/tidebroker-worker/gog",
    "timeoutMs": 30000,
    "maxOutputBytes": 1048576
  }
}
```

Tidebroker bundles no `gog` executable or source. Administrators choosing this mode
must provision the absolute executable path and private config root themselves. The
included safety-profile YAML is a build recipe, not a vendored CLI. Invalid or
ambiguous backend configurations fail startup; Tidebroker never falls back between modes.

The shared socket directory is pre-created by the administrator, owned by the
worker, assigned to a dedicated group containing only the worker and Gateway,
and grants group execute without group write. Group mode creates a `0660` socket.
Owner mode remains the default and creates a `0600` socket.

## Worker service

```ini
[Unit]
Description=Tidebroker isolated credential worker
After=network-online.target

[Service]
Type=simple
User=tidebroker-worker
Group=tidebroker
UMask=0077
ExecStart=/usr/local/bin/tidebroker-worker /etc/tidebroker/worker.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=40
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/tidebroker /var/lib/tidebroker-worker
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

The worker prints only stable readiness/result codes and the fixed loopback start
page URL for an interactive connection. It never prints configuration, commands, provider
responses, or exception objects. A supervisor can run
`tidebroker-worker --check /etc/tidebroker/worker.json`; success requires
secure key files and a protected live socket.

## OpenClaw activation

The plugin configuration contains no provider identity or credential. It uses
opaque deployment identifiers and trusted `agentId` workspace selection:

```json
{
  "enabled": true,
  "workerSocketPath": "/run/tidebroker/worker.sock",
  "workerSocketAccess": "group",
  "workerSocketGroupId": 2000,
  "subjectMappingsPath": "/var/lib/openclaw/tidebroker/subjects.json",
  "workspaceMembershipsPath": "/var/lib/openclaw/tidebroker/memberships.json",
  "gatewayAuditRoot": "/var/lib/openclaw/tidebroker/audit",
  "workerAccountDiscovery": true,
  "grant": {
    "issuer": "openclaw-gateway",
    "audience": "tidebroker-worker",
    "keyFile": "/run/openclaw-secrets/tidebroker-grant.key"
  },
  "agentWorkspaces": [
    { "agentId": "company", "workspaceId": "ws_01EXAMPLE" }
  ]
}
```

With `workerAccountDiscovery`, account metadata stays inside the worker boundary.
Each tool call first sends an authenticated, single-use discovery grant bound to
the trusted subject and selected workspace. Static `accounts` remain supported for
deployments that deliberately manage the non-secret projection themselves.

## Connect Google Calendar

Create an owner-only connection request containing opaque deployment identifiers
and the path to the existing trusted membership file:

```json
{
  "version": 1,
  "subjectId": "usr_01EXAMPLE0000000",
  "workspaceId": "ws_01EXAMPLE",
  "workspaceMembershipsPath": "/var/lib/tidebroker-worker/provisioning/memberships.json"
}
```

Deployment automation must copy the authoritative opaque membership snapshot into
the worker boundary as an owner-only file; browser or model input must never create
or modify it. Run the worker's one-shot connection mode with the worker configuration and
connection-request file paths. Open only the fixed loopback start page printed by
the process. The request fails closed unless the opaque subject is a current member
of that workspace. Google returns the authorization result with `form_post`; the
worker validates state, PKCE, signed issuer/audience/nonce claims and exact scopes,
then encrypts the refresh material and creates the private binding. No credential
is printed or accepted through chat, argv, a URL, logs, or audit.

```bash
tidebroker-worker --connect-google /etc/tidebroker/worker.json /etc/tidebroker/connect-google.json
```

The terminal success code is `GOOGLE_CONNECT_COMPLETE`. Restarting the OpenClaw
Gateway is unnecessary when `workerAccountDiscovery` is enabled.

## Revoke a connected account

Create an owner-only request with the opaque handle from worker-private operational
inventory, then run one-shot revocation:

```json
{ "version": 1, "credentialHandle": "cred_01EXAMPLE" }
```

```bash
tidebroker-worker --revoke /etc/tidebroker/worker.json /etc/tidebroker/revoke-google.json
```

Revocation attempts Google's fixed revocation endpoint using a POST body, always
increments and locally revokes the encrypted generation, disables discovery, and
appends a minimized audit event. `CREDENTIAL_REVOKED_LOCAL` means provider revocation
could not be confirmed but the local credential is already unusable.

`google_calendar_events_list` is omitted unless all deployment files, socket
permissions, trusted actor context, and agent/workspace selection pass. Its input
schema exposes only `today` and `maxResults`. Background, cron, public, unmapped,
and membership-denied runs receive no usable Calendar capability.

## Approval-gated Calendar writes

Version 0.6 adds `google_calendar_event_create`,
`google_calendar_event_update`, and `google_calendar_event_delete`. These tools
are available only to trusted interactive requesters with an exact
subject/workspace/account binding. Every call requires OpenClaw's durable plugin
approval UI with `allow-once` or `deny`; `allow-always` is deliberately not
offered.

Approval is bound to the requester, tool call id, operation, and canonical
payload digest. The approval ticket is single-use and expires after two minutes.
The same digest is authenticated in the short-lived worker grant, so input
changed after approval fails closed at the isolated worker boundary. Mutating
operations also fail closed when audit storage is unavailable.

Google consent uses `calendar.events` plus read-only CalendarList and Calendars
metadata scopes required by gog's timezone/calendar resolution. Existing read-only
connections must reconnect once after upgrading; no deployment may silently
upgrade an existing credential's scope. Reconnecting increments the credential
generation so pre-reconnect grants cannot become valid again.

Each collaborator must have a separate deployment-owned subject mapping and
workspace membership. Never share one raw host identity or one approval token
between operators. Once both mappings exist, either collaborator can
approve their own exact interactive write requests without handling OAuth
tokens, API calls, or worker configuration.

## Gmail search, read, and send

Version 1.0 exposes `google_gmail_messages_search`, `google_gmail_message_get`, and
`google_gmail_message_send` using the same opaque actor/workspace/account binding
and encrypted worker credential. Enable `gmail.googleapis.com` in the existing
deployment project and reconnect once with `gmail.readonly` and `gmail.send`.

Search is capped at 25 results. Reads use `gog gmail messages search` and
`gog gmail get --sanitize-content`; output is bounded, wrapped as untrusted, and
stripped of credential-shaped fields. Attachments are not downloaded or exposed.

Sending accepts address-only recipients, one subject, and a bounded plain-text
body. It requires a critical `allow-once` approval bound to the exact requester,
tool call, recipients, subject, body digest, account generation, and worker grant.
The body is delivered to `gog` through stdin rather than argv. There is no ambient
send authority and no `allow-always` decision.
