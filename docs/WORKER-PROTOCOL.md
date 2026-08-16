# Credential worker deployment protocol

The SDK defines the authenticated application protocol; the deployment supplies
the process/container transport. Never expose the worker directly to clients.

1. The Gateway maps the trusted host tuple to a random local `usr_...` subject.
2. A host-owned workspace adapter resolves `ws_...` and verifies membership.
3. `ActorBroker` resolves one exact enabled account/action binding. It may consult
   a non-secret metadata projection, but never needs credential-store access.
4. It issues a 60-second authenticated grant bound to issuer, audience, opaque
   subject, principal kind, workspace, connector, action, handle, generation,
   request correlation, and one-time nonce.
5. Send the grant and typed operation input over a protected local socket or mTLS
   request body. Never use raw identity headers, query strings, argv, or ambient
   environment state as the authorization protocol.
6. The worker authenticates the grant, atomically claims the nonce, redeems the
   exact encrypted record, rechecks generation immediately before the provider
   call, executes one registered operation, sanitizes output, and appends a
   closed-schema audit event.

`UnixCredentialWorkerServer` uses a mode-`0600` socket inside an owner-only
directory, length-prefixed bounded JSON frames, stable closed errors, request
timeouts, and bounded concurrency. It never accepts identity or credential
headers. A crashed worker deliberately leaves the socket path in place so restart
automation must prove the old process is gone before removing that exact socket.

Run the worker with a different OS identity or container, a private state root,
no inherited cloud/CLI environment, fixed executable paths, bounded resources,
and only active/rotation encryption keys. Use a durable atomic replay store and
append-only audit sink in multi-process deployments; in-memory adapters are for
tests and single-process development only.

The worker also exposes one non-credential operation, `account.binding.resolve`.
It requires a normal authenticated, replay-protected, short-lived grant bound to
the exact opaque subject/workspace and a fixed discovery handle. The result is
only the matching non-secret account/handle/generation policy record. The Gateway
cannot list all bindings and cannot read the worker-private binding file.

Google Workspace operations require a fixed-path `gog` binary compiled with the
repository's baked safety profile. The worker refreshes the encrypted OAuth record
and injects the short-lived access token into a closed child environment recognized
by `gog`; it never persists the token in gog state or places it in argv. The child
inherits no ambient cloud, account, HOME, or PATH state. Message bodies use stdin.
Runtime exact-command flags, read-only/Gmail-no-send guards, bounded output, and
secret-field stripping provide defense in depth. Pre-provisioned opaque gog profiles
remain supported for compatibility, but are not the production OAuth path.
