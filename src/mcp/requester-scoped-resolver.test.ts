import { describe, expect, it, vi } from "vitest";
import { createRequesterScopedMcpResolver } from "./requester-scoped-resolver.js";

describe("createRequesterScopedMcpResolver", () => {
  it("derives the actor only from trusted runtime context", async () => {
    const resolve = vi.fn(() => ({
      url: "https://broker.example.test/mcp",
      headers: { Authorization: "Bearer hidden" },
    }));
    const resolver = createRequesterScopedMcpResolver({
      serverName: "solvely-google",
      bindings: { resolve },
    });

    await expect(
      resolver.resolve({
        requesterSenderId: "  operator-a@example.test  ",
        messageChannel: "webchat",
      }),
    ).resolves.toEqual({
      url: "https://broker.example.test/mcp",
      headers: { authorization: "Bearer hidden" },
    });
    expect(resolve).toHaveBeenCalledWith({
      actorId: '["webchat",null,"operator-a@example.test"]',
      serverName: "solvely-google",
      messageChannel: "webchat",
    });
  });

  it.each(["", "   ", "actor\nforged"])("fails closed for invalid actor %j", async (actor) => {
    const resolve = vi.fn();
    const resolver = createRequesterScopedMcpResolver({
      serverName: "solvely-google",
      bindings: { resolve },
    });

    await expect(resolver.resolve({ requesterSenderId: actor })).resolves.toBeNull();
    expect(resolve).not.toHaveBeenCalled();
  });

  it("allows loopback HTTP for a local broker", async () => {
    const resolver = createRequesterScopedMcpResolver({
      serverName: "local-broker",
      bindings: { resolve: () => ({ url: "http://127.0.0.1:43123/mcp" }) },
    });

    await expect(resolver.resolve({ requesterSenderId: "actor-1" })).resolves.toEqual({
      url: "http://127.0.0.1:43123/mcp",
    });
  });

  it.each([
    "http://broker.example.test/mcp",
    "file:///tmp/socket",
    "https://user:password@broker.example.test/mcp",
  ])("rejects unsafe broker URL %s", async (url) => {
    const resolver = createRequesterScopedMcpResolver({
      serverName: "solvely-google",
      bindings: { resolve: () => ({ url }) },
    });

    await expect(resolver.resolve({ requesterSenderId: "actor-1" })).rejects.toThrow();
  });

  it("rejects unsafe transport headers", async () => {
    const resolver = createRequesterScopedMcpResolver({
      serverName: "solvely-google",
      bindings: {
        resolve: () => ({
          url: "https://broker.example.test/mcp",
          headers: { Host: "attacker.example", "x-safe": "ok" },
        }),
      },
    });

    await expect(resolver.resolve({ requesterSenderId: "actor-1" })).rejects.toThrow(
      "header is not allowed",
    );
  });
});
