import { access, mkdtemp, mkdir, rename, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ActorCliExecutor,
  CliExecutionError,
  createActorCliBinding,
  createAllowlistPolicy,
} from "./index.js";
import {
  defineAccountId,
  defineCredentialHandle,
  defineWorkspaceId,
  humanPrincipal,
  trustedActorFromHostContext,
  type ConnectorExecutionContext,
} from "../core/index.js";

const temporaryRoots: string[] = [];
const passThrough = (text: string): string => text;

function contextFor(sender = "actor-a"): ConnectorExecutionContext {
  const actor = trustedActorFromHostContext({
    requesterSenderId: sender,
    messageChannel: "test",
    agentAccountId: "gateway",
  });
  if (!actor.ok) throw new Error("invalid test actor");
  return Object.freeze({
    principal: humanPrincipal(actor.actorId),
    workspaceId: defineWorkspaceId("company"),
    accountId: defineAccountId(`${sender}-account`),
    credentialHandle: defineCredentialHandle(`${sender}-credential`),
  });
}

async function bindingFixture() {
  const root = await mkdtemp(join(tmpdir(), "actor-cli-test-"));
  temporaryRoots.push(root);
  const actorDirectory = join(root, "actor-a");
  await mkdir(actorDirectory);
  const executionContext = contextFor();
  return {
    root,
    actorDirectory,
    executionContext,
    binding: await createActorCliBinding({
      configRoot: root,
      configDirectory: actorDirectory,
      executionContext,
    }),
  };
}

function nodePolicy(script: string, options: { allowPositionals?: boolean } = {}) {
  return createAllowlistPolicy({
    node: {
      path: process.execPath,
      operations: {
        run: {
          argvPrefix: ["-e", script],
          allowPositionals: options.allowPositionals,
        },
      },
    },
  });
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true })));
});

describe("actor CLI binding", () => {
  it("accepts a real actor directory contained by the configured root", async () => {
    const fixture = await bindingFixture();
    expect(Object.isFrozen(fixture.binding)).toBe(true);
    expect(Object.keys(fixture.binding)).toHaveLength(0);
  });

  it("rejects traversal and symlink escapes", async () => {
    const fixture = await bindingFixture();
    const outside = await mkdtemp(join(tmpdir(), "actor-cli-outside-"));
    temporaryRoots.push(outside);

    await expect(
      createActorCliBinding({
        configRoot: fixture.root,
        configDirectory: outside,
        executionContext: fixture.executionContext,
      }),
    ).rejects.toMatchObject({ code: "CLI_INVALID_BINDING" });

    const link = join(fixture.root, "outside-link");
    await symlink(outside, link, "dir");
    await expect(
      createActorCliBinding({
        configRoot: fixture.root,
        configDirectory: link,
        executionContext: fixture.executionContext,
      }),
    ).rejects.toMatchObject({ code: "CLI_INVALID_BINDING" });
  });
});

describe("allowlist policy", () => {
  it("denies unknown executables, operations, and flags", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: createAllowlistPolicy({
        tool: {
          path: process.execPath,
          operations: { read: { allowedFlags: ["--json"] } },
        },
      }),
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, contextFor(), { executable: "other", operation: "read" }),
    ).rejects.toMatchObject({ code: "CLI_POLICY_DENIED" });
    await expect(
      executor.execute(binding, contextFor(), { executable: "tool", operation: "write" }),
    ).rejects.toMatchObject({ code: "CLI_POLICY_DENIED" });
    await expect(
      executor.execute(binding, contextFor(), {
        executable: "tool",
        operation: "read",
        argv: ["--verbose"],
      }),
    ).rejects.toMatchObject({ code: "CLI_POLICY_DENIED" });
  });

  it("always rejects common credential-bearing flags", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: createAllowlistPolicy({
        tool: {
          path: process.execPath,
          operations: {
            read: { allowedFlags: ["--token"], allowPositionals: true },
          },
        },
      }),
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, contextFor(), {
        executable: "tool",
        operation: "read",
        argv: ["--token=not-a-real-token"],
      }),
    ).rejects.toMatchObject({ code: "CLI_POLICY_DENIED" });
  });

  it("applies credential-flag rejection to custom policy results", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: () => ({
        executablePath: process.execPath,
        argv: ["--api-key", "not-a-real-key"],
      }),
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, contextFor(), { executable: "ignored", operation: "ignored" }),
    ).rejects.toMatchObject({ code: "CLI_POLICY_DENIED" });
  });
});

describe("actor CLI executor", () => {
  it("requires an explicit output sanitizer", async () => {
    expect(
      () => new ActorCliExecutor({ policy: nodePolicy("process.exit(0)") } as never),
    ).toThrow(expect.objectContaining({ code: "CLI_INVALID_INVOCATION" }));
  });

  it("rejects a binding used with another actor's execution context", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: nodePolicy("process.stdout.write('must-not-run')"),
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, contextFor("actor-b"), {
        executable: "node",
        operation: "run",
      }),
    ).rejects.toMatchObject({ code: "CLI_BINDING_MISMATCH" });
  });

  it("rejects config-directory replacement after binding", async () => {
    const { binding, actorDirectory, root, executionContext } = await bindingFixture();
    const outside = await mkdtemp(join(tmpdir(), "actor-cli-replacement-"));
    temporaryRoots.push(outside);
    await rename(actorDirectory, join(root, "actor-a-original"));
    await symlink(outside, actorDirectory, "dir");
    const executor = new ActorCliExecutor({
      policy: nodePolicy("process.exit(0)"),
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, executionContext, {
        executable: "node",
        operation: "run",
      }),
    ).rejects.toMatchObject({ code: "CLI_INVALID_BINDING" });
  });

  it("does not spawn after cancellation during asynchronous policy", async () => {
    const { binding, executionContext } = await bindingFixture();
    let releasePolicy!: () => void;
    const policyGate = new Promise<void>((resolve) => { releasePolicy = resolve; });
    const controller = new AbortController();
    const executor = new ActorCliExecutor({
      policy: async () => {
        await policyGate;
        return { executablePath: process.execPath, argv: ["-e", "process.exit(0)"] };
      },
      redact: passThrough,
    });
    const execution = executor.execute(
      binding,
      executionContext,
      { executable: "node", operation: "run" },
      { signal: controller.signal },
    );
    controller.abort();
    releasePolicy();

    await expect(execution).rejects.toMatchObject({ code: "CLI_ABORTED" });
  });

  it("passes argv literally without a shell and exposes only the config-path environment", async () => {
    const { binding, actorDirectory } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: nodePolicy(
        "process.stdout.write(JSON.stringify({arg:process.argv[1],home:process.env.HOME,leak:process.env.ACTOR_CLI_TEST_SECRET}))",
        { allowPositionals: true },
      ),
      redact: passThrough,
    });
    process.env.ACTOR_CLI_TEST_SECRET = "must-not-leak";
    try {
      const result = await executor.execute(binding, contextFor(), {
        executable: "node",
        operation: "run",
        argv: ["$(printf shell-injection)"],
      });
      expect(JSON.parse(result.stdout)).toEqual({
        arg: "$(printf shell-injection)",
        home: actorDirectory,
      });
      expect(result.exitCode).toBe(0);
    } finally {
      delete process.env.ACTOR_CLI_TEST_SECRET;
    }
  });

  it("supports an async custom policy", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: async ({ invocation }) => ({
        executablePath: process.execPath,
        argv: ["-e", "process.stdout.write(process.argv[1])", invocation.operation],
      }),
      redact: passThrough,
    });
    await expect(
      executor.execute(binding, contextFor(), { executable: "node", operation: "custom-policy" }),
    ).resolves.toMatchObject({ stdout: "custom-policy" });
  });

  it("redacts successful and nonzero output", async () => {
    const { binding } = await bindingFixture();
    const redact = (text: string) => text.replaceAll("sensitive", "[REDACTED]");
    const success = new ActorCliExecutor({
      policy: nodePolicy("process.stdout.write('sensitive')"),
      redact,
    });
    await expect(
      success.execute(binding, contextFor(), { executable: "node", operation: "run" }),
    ).resolves.toMatchObject({ stdout: "[REDACTED]" });

    const failure = new ActorCliExecutor({
      policy: nodePolicy("process.stderr.write('sensitive');process.exit(7)"),
      redact,
    });
    await expect(
      failure.execute(binding, contextFor(), { executable: "node", operation: "run" }),
    ).rejects.toMatchObject({
      code: "CLI_EXIT_NONZERO",
      exitCode: 7,
    });
  });

  it("enforces timeout and pre-aborted signals with stable errors", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: nodePolicy("setTimeout(()=>{},10_000)"),
      timeoutMs: 25,
      redact: passThrough,
    });
    await expect(
      executor.execute(binding, contextFor(), { executable: "node", operation: "run" }),
    ).rejects.toMatchObject({ code: "CLI_TIMEOUT" });

    const controller = new AbortController();
    controller.abort();
    await expect(
      executor.execute(
        binding,
        contextFor(),
        { executable: "node", operation: "run" },
        { signal: controller.signal },
      ),
    ).rejects.toMatchObject({ code: "CLI_ABORTED" });
  });

  it("terminates output that exceeds the byte bound", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: nodePolicy("process.stdout.write('x'.repeat(4096))"),
      maxOutputBytes: 32,
      redact: passThrough,
    });
    await expect(
      executor.execute(binding, contextFor(), { executable: "node", operation: "run" }),
    ).rejects.toMatchObject({ code: "CLI_OUTPUT_LIMIT" });
  });

  it.runIf(process.platform !== "win32")("terminates the full POSIX process group", async () => {
    const { binding, executionContext, root } = await bindingFixture();
    const marker = join(root, "descendant-survived");
    const descendant = `setTimeout(()=>require('node:fs').writeFileSync(${JSON.stringify(marker)},'x'),150)`;
    const parent = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore'});setTimeout(()=>{},10000)`;
    const executor = new ActorCliExecutor({
      policy: nodePolicy(parent),
      timeoutMs: 25,
      redact: passThrough,
    });

    await expect(
      executor.execute(binding, executionContext, { executable: "node", operation: "run" }),
    ).rejects.toMatchObject({ code: "CLI_TIMEOUT" });
    await new Promise((resolve) => setTimeout(resolve, 225));
    await expect(access(marker)).rejects.toBeDefined();
  });

  it("returns deterministic spawn errors without exposing argv", async () => {
    const { binding } = await bindingFixture();
    const executor = new ActorCliExecutor({
      policy: () => ({
        executablePath: "/definitely/not/an/executable",
        argv: ["sensitive positional value"],
      }),
      redact: passThrough,
    });
    const error = await executor
      .execute(binding, contextFor(), { executable: "missing", operation: "run" })
      .catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(CliExecutionError);
    expect(error).toMatchObject({ code: "CLI_SPAWN_FAILED" });
    expect(String(error)).not.toContain("sensitive positional value");
  });
});
