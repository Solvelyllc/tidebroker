import { chmod, lstat, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { spawn } from "node:child_process";
import { defineAccountId, defineConnectorId, defineCredentialHandle, defineWorkspaceId } from "../core/policy.js";
import { defineSubjectId } from "../core/subject.js";
import { CredentialRevocationManager, EncryptedCredentialStore, StaticCredentialEncryptionKeys } from "../credentials/index.js";
import { FileAuditSink, FileCredentialRecordBackend, FileGrantReplayStore } from "../durable/index.js";
import { CredentialGrantIssuer, CredentialGrantVerifier } from "./grant.js";
import { UnixCredentialWorkerClient, UnixCredentialWorkerServer } from "./transport.js";
import { IsolatedCredentialWorker } from "./worker.js";

describe("Unix credential worker transport", () => {
  it("supports a protected dedicated group socket for separate OS identities", async () => {
    if (typeof process.getgid !== "function") return;
    const root = await mkdtemp(join(tmpdir(), "credential-worker-group-")); await chmod(root, 0o710);
    const connectorId = defineConnectorId("google-gog");
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret: new Uint8Array(32).fill(1), issuer: "gateway", audience: "worker" }), credentials: {} as EncryptedCredentialStore, replay: new FileGrantReplayStore(join(root, "replay")), audit: new FileAuditSink(join(root, "audit")) }, [{ connectorId, action: "calendar.events.list", mutating: false, execute: async () => ({}) }]);
    const socketPath = join(root, "worker.sock"); const server = new UnixCredentialWorkerServer({ socketPath, worker, socketAccess: "group", socketGroupId: process.getgid() });
    await server.start();
    const socket = await lstat(socketPath); expect(socket.mode & 0o777).toBe(0o660); expect(socket.gid).toBe(process.getgid());
    await server.stop();
  });

  it("recovers only an inactive socket left by a crashed supervised process", async () => {
    const root = await mkdtemp(join(tmpdir(), "credential-worker-stale-"));
    const socketPath = join(root, "worker.sock");
    const child = spawn(process.execPath, ["-e", "const n=require('node:net');const s=n.createServer();s.listen(process.argv[1],()=>process.stdout.write('READY\\n'));setInterval(()=>{},10000)", socketPath], { stdio: ["ignore", "pipe", "ignore"] });
    await new Promise<void>((resolve, reject) => { child.stdout.once("data", () => resolve()); child.once("error", reject); });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("close", () => resolve()));
    expect((await lstat(socketPath)).isSocket()).toBe(true);
    const connectorId = defineConnectorId("google-gog");
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret: new Uint8Array(32).fill(1), issuer: "gateway", audience: "worker" }), credentials: {} as EncryptedCredentialStore, replay: new FileGrantReplayStore(join(root, "replay")), audit: new FileAuditSink(join(root, "audit")) }, [{ connectorId, action: "calendar.events.list", mutating: false, execute: async () => ({}) }]);
    const server = new UnixCredentialWorkerServer({ socketPath, worker, recoverStaleSocket: true });
    await expect(server.start()).resolves.toBeUndefined();
    await server.stop();
  });

  it("survives restart, rejects replay, and enforces revocation before execution", async () => {
    const root = await mkdtemp(join(tmpdir(), "credential-worker-ipc-"));
    const socketPath = join(root, "worker.sock");
    const connectorId = defineConnectorId("google-gog");
    const subjectId = defineSubjectId("usr_0123456789abcdef");
    const workspaceId = defineWorkspaceId("ws_solvely");
    const credentialHandle = defineCredentialHandle("cred_calendar");
    const accountId = defineAccountId("acct_calendar");
    const audit = new FileAuditSink(join(root, "audit"));
    const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(join(root, "credentials"), join(root, "metadata")), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(8)));
    await credentials.store({ subjectId, principalKind: "human", workspaceId, connectorId, accountId, credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: "/worker/profile", accountAlias: "acct_opaque123" });
    const secret = new Uint8Array(32).fill(6);
    let nonce = 0;
    const issuer = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => `non_${++nonce}` });
    const execute = vi.fn(async () => ({ events: [{ id: "event_1" }] }));
    const makeWorker = () => new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new FileGrantReplayStore(join(root, "replay"), () => 101), audit }, [{ connectorId, action: "calendar.events.list", mutating: false, execute }]);
    const client = new UnixCredentialWorkerClient({ socketPath, newRequestId: () => `ipc_${nonce}` });
    const claims = { subjectId, principalKind: "human" as const, workspaceId, connectorId, action: "calendar.events.list", credentialHandle, credentialGeneration: 1, requestId: "req_1" };
    const grant = issuer.issue(claims);

    const first = new UnixCredentialWorkerServer({ socketPath, worker: makeWorker() });
    await first.start();
    expect((await lstat(socketPath)).mode & 0o077).toBe(0);
    await expect(client.execute({ connectorId, action: claims.action, grant, input: { today: true } })).resolves.toEqual({ events: [{ id: "event_1" }] });
    await first.stop();

    const restarted = new UnixCredentialWorkerServer({ socketPath, worker: makeWorker() });
    await restarted.start();
    await expect(client.execute({ connectorId, action: claims.action, grant, input: {} })).rejects.toMatchObject({ code: "WORKER_GRANT_REPLAYED" });
    const stale = issuer.issue({ ...claims, requestId: "req_2" });
    await new CredentialRevocationManager({ credentials, audit }).revoke(credentialHandle, "req_revoke");
    await expect(client.execute({ connectorId, action: claims.action, grant: stale, input: {} })).rejects.toMatchObject({ code: "WORKER_CREDENTIAL_DENIED" });
    expect(execute).toHaveBeenCalledTimes(1);
    await restarted.stop();
  });

  it("does not allow a grant for another opaque subject to redeem the record", async () => {
    const root = await mkdtemp(join(tmpdir(), "credential-worker-cross-actor-"));
    const socketPath = join(root, "worker.sock");
    const connectorId = defineConnectorId("google-gog"); const workspaceId = defineWorkspaceId("ws_solvely");
    const credentialHandle = defineCredentialHandle("cred_calendar");
    const credentials = new EncryptedCredentialStore(new FileCredentialRecordBackend(join(root, "credentials"), join(root, "metadata")), new StaticCredentialEncryptionKeys("key_1", new Uint8Array(32).fill(2)));
    await credentials.store({ subjectId: defineSubjectId("usr_aaaaaaaaaaaaaaaa"), principalKind: "human", workspaceId, connectorId, accountId: defineAccountId("acct_calendar"), credentialHandle, generation: 1, scopes: ["calendar.readonly"] }, { kind: "gog-profile", configDirectory: "/worker/profile", accountAlias: "acct_opaque123" });
    const secret = new Uint8Array(32).fill(1); const execute = vi.fn(async () => ({}));
    const worker = new IsolatedCredentialWorker({ verifier: new CredentialGrantVerifier({ secret, issuer: "gateway", audience: "worker", now: () => 101 }), credentials, replay: new FileGrantReplayStore(join(root, "replay"), () => 101), audit: new FileAuditSink(join(root, "audit")) }, [{ connectorId, action: "calendar.events.list", mutating: false, execute }]);
    const server = new UnixCredentialWorkerServer({ socketPath, worker }); await server.start();
    const grant = new CredentialGrantIssuer({ secret, issuer: "gateway", audience: "worker", now: () => 100, nonce: () => "non_cross_actor" }).issue({ subjectId: defineSubjectId("usr_bbbbbbbbbbbbbbbb"), principalKind: "human", workspaceId, connectorId, action: "calendar.events.list", credentialHandle, credentialGeneration: 1, requestId: "req_cross" });
    await expect(new UnixCredentialWorkerClient({ socketPath, newRequestId: () => "ipc_cross" }).execute({ connectorId, action: "calendar.events.list", grant, input: {} })).rejects.toMatchObject({ code: "WORKER_CREDENTIAL_DENIED" });
    expect(execute).not.toHaveBeenCalled();
    await server.stop();
  });
});
