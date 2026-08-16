#!/usr/bin/env node
import { checkCredentialWorkerService, createCredentialWorkerService, loadCredentialWorkerServiceConfig } from "./bootstrap.js";
import { loadGoogleConnectionConfig, runGoogleAccountConnection } from "./google-provisioning.js";
import { loadCredentialRevocationRequest, runCredentialRevocation } from "./revoke.js";

async function main(): Promise<void> {
  if (process.argv[2] === "--connect-google") {
    if (process.argv.length !== 5) throw new Error("GOOGLE_CONNECTION_CONFIG_REQUIRED");
    await runGoogleAccountConnection(await loadCredentialWorkerServiceConfig(process.argv[3]!), await loadGoogleConnectionConfig(process.argv[4]!));
    process.stdout.write("GOOGLE_CONNECT_COMPLETE\n"); return;
  }
  if (process.argv[2] === "--revoke") {
    if (process.argv.length !== 5) throw new Error("REVOCATION_REQUEST_REQUIRED");
    const result = await runCredentialRevocation(await loadCredentialWorkerServiceConfig(process.argv[3]!), await loadCredentialRevocationRequest(process.argv[4]!));
    process.stdout.write(result.providerRevoked ? "CREDENTIAL_REVOKED\n" : "CREDENTIAL_REVOKED_LOCAL\n"); return;
  }
  const healthCheck = process.argv[2] === "--check";
  const configPath = healthCheck ? process.argv[3] : process.argv.length === 3 ? process.argv[2] : undefined;
  if (!configPath) throw new Error("WORKER_CONFIG_REQUIRED");
  if (healthCheck) {
    if (!await checkCredentialWorkerService(await loadCredentialWorkerServiceConfig(configPath))) throw new Error("WORKER_UNHEALTHY");
    process.stdout.write("WORKER_HEALTHY\n");
    return;
  }
  const server = await createCredentialWorkerService(await loadCredentialWorkerServiceConfig(configPath));
  await server.start();
  process.stdout.write("WORKER_READY\n");
  await new Promise<void>((resolve) => {
    const stop = () => { process.removeListener("SIGINT", stop); process.removeListener("SIGTERM", stop); void server.stop().finally(resolve); };
    process.once("SIGINT", stop); process.once("SIGTERM", stop);
  });
}

void main().catch(() => {
  const mode = process.argv[2];
  process.stderr.write(mode === "--connect-google" ? "GOOGLE_CONNECT_FAILED\n" : mode === "--revoke" ? "CREDENTIAL_REVOKE_FAILED\n" : "WORKER_START_FAILED\n");
  process.exitCode = 1;
});
