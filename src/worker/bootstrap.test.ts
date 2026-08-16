import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkCredentialWorkerService, createCredentialWorkerService, loadCredentialWorkerServiceConfig, validateCredentialWorkerServiceConfig } from "./bootstrap.js";
import { readSecureKeyFile } from "./secure-key-files.js";
import { fileSha256 } from "../../test-fixtures/fake-gog-helper.js";

describe("credential worker bootstrap", () => {
  it("loads a closed path-only config and starts the runnable service", async () => {
    const root = await mkdtemp(join(tmpdir(), "worker-bootstrap-"));
    const keyPath = join(root, "grant.key"); const encryptionPath = join(root, "encryption.key");
    await writeFile(keyPath, Buffer.alloc(32, 1), { mode: 0o600 }); await writeFile(encryptionPath, Buffer.alloc(32, 2), { mode: 0o600 });
    const gogRoot = join(root, "gog"); await mkdir(gogRoot, { mode: 0o700 });
    const configPath = join(root, "worker.json");
    const config = { version: 1, socketPath: join(root, "worker.sock"), recoverStaleSocket: true, credentialRoot: join(root, "credentials"), metadataRoot: join(root, "metadata"), replayRoot: join(root, "replay"), auditRoot: join(root, "audit"), outcomeRoot: join(root, "outcomes"), grant: { issuer: "gateway", audience: "worker", keyFile: keyPath }, encryption: { activeKeyId: "key_1", keys: [{ id: "key_1", keyFile: encryptionPath }] }, googleExecution: { backend: "gog", executablePath: "/bin/false", executableSha256: await fileSha256("/bin/false"), configRoot: gogRoot }, limits: { maxConcurrent: 2 } };
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
    const loaded = await loadCredentialWorkerServiceConfig(configPath);
    expect(JSON.stringify(loaded)).not.toContain(Buffer.alloc(32, 1).toString("base64"));
    const server = await createCredentialWorkerService(loaded);
    await expect(checkCredentialWorkerService(loaded)).resolves.toBe(false);
    await expect(server.start()).resolves.toBeUndefined();
    await expect(checkCredentialWorkerService(loaded)).resolves.toBe(true);
    await server.stop();
  });

  it("rejects key files readable by another account", async () => {
    const root = await mkdtemp(join(tmpdir(), "worker-key-mode-")); const keyPath = join(root, "bad.key");
    await writeFile(keyPath, Buffer.alloc(32, 3), { mode: 0o600 }); await chmod(keyPath, 0o644);
    await expect(readSecureKeyFile(keyPath)).rejects.toThrow("SECURE_KEY_FILE_INVALID");
  });

  it("accepts an explicitly configured external gog runtime for the OAuth Google worker", async () => {
    const root = await mkdtemp(join(tmpdir(), "worker-oauth-bootstrap-")); const keyPath = join(root, "grant.key"); const encryptionPath = join(root, "encryption.key");
    const clientIdPath = join(root, "client-id"); const clientSecretPath = join(root, "client-secret");
    const gogRoot = join(root, "gog"); const gogPath = join(root, "gog-safe"); await mkdir(gogRoot, { mode: 0o700 }); await writeFile(gogPath, "#!/bin/false\n", { mode: 0o700 });
    await writeFile(keyPath, Buffer.alloc(32, 4), { mode: 0o600 }); await writeFile(encryptionPath, Buffer.alloc(32, 5), { mode: 0o600 });
    await writeFile(clientIdPath, "synthetic-client-id", { mode: 0o600 }); await writeFile(clientSecretPath, "synthetic-client-secret", { mode: 0o600 });
    const config = validateCredentialWorkerServiceConfig({ version: 1, socketPath: join(root, "worker.sock"), recoverStaleSocket: true,
      credentialRoot: join(root, "credentials"), metadataRoot: join(root, "metadata"), replayRoot: join(root, "replay"), auditRoot: join(root, "audit"), outcomeRoot: join(root, "outcomes"), oauthStateRoot: join(root, "oauth"), accountBindingsPath: join(root, "accounts", "bindings.json"),
      grant: { issuer: "gateway", audience: "worker", keyFile: keyPath }, encryption: { activeKeyId: "key_1", keys: [{ id: "key_1", keyFile: encryptionPath }] },
      googleExecution: { backend: "gog", executablePath: gogPath, executableSha256: await fileSha256(gogPath), configRoot: gogRoot },
      googleOAuth: { clientIdFile: clientIdPath, clientSecretFile: clientSecretPath, redirectUri: "http://127.0.0.1:8765/oauth/google/callback" } });
    const server = await createCredentialWorkerService(config); await expect(server.start()).resolves.toBeUndefined(); await server.stop();
  });

  it("accepts direct Google execution without any gog path and rejects ambiguous backends", () => {
    const base = { version: 1, socketPath: "/tmp/tidebroker.sock", recoverStaleSocket: true, credentialRoot: "/tmp/credentials", metadataRoot: "/tmp/metadata", replayRoot: "/tmp/replay", auditRoot: "/tmp/audit", outcomeRoot: "/tmp/outcomes", grant: { issuer: "gateway", audience: "worker", keyFile: "/tmp/grant.key" }, encryption: { activeKeyId: "key_1", keys: [{ id: "key_1", keyFile: "/tmp/encryption.key" }] } };
    expect(validateCredentialWorkerServiceConfig({ ...base, googleExecution: { backend: "direct" } }).googleExecution).toEqual({ backend: "direct" });
    expect(() => validateCredentialWorkerServiceConfig({ ...base, googleExecution: { backend: "direct", executablePath: "/bin/gog" } })).toThrow("WORKER_CONFIG_INVALID");
    expect(() => validateCredentialWorkerServiceConfig({ ...base, googleExecution: { backend: "automatic" } })).toThrow("WORKER_CONFIG_INVALID");
  });
});
