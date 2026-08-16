import { describe, expect, it } from "vitest";
import { McpToolQuarantine, mcpSchemaFingerprint } from "./tool-quarantine.js";

const schema = {
  type: "object",
  additionalProperties: false,
  properties: { query: { type: "string", maxLength: 100 } },
  required: ["query"],
};

function policy() {
  return new McpToolQuarantine([{
    name: "search",
    schemaSha256: mcpSchemaFingerprint(schema),
    privilege: "read",
    approval: "none",
  }]);
}

describe("McpToolQuarantine", () => {
  it("allows an exact deployment-approved schema and classification", () => {
    const reordered = { required: ["query"], properties: { query: { maxLength: 100, type: "string" } }, additionalProperties: false, type: "object" };
    expect(policy().inspect([{ name: "search", inputSchema: reordered, privilege: "read", approval: "none" }])).toEqual([{
      status: "allowed",
      name: "search",
      schemaSha256: mcpSchemaFingerprint(schema),
    }]);
  });

  it("quarantines schema drift without accepting the new fingerprint", () => {
    const changed = { ...schema, properties: { query: { type: "string", maxLength: 10_000 } } };
    const quarantine = policy();
    expect(quarantine.inspect([{ name: "search", inputSchema: changed, privilege: "read", approval: "none" }])).toEqual([{
      status: "quarantined",
      name: "search",
      reason: "schema-drift",
    }]);
    expect(() => quarantine.requireAllowed({ name: "search", inputSchema: changed, privilege: "read", approval: "none" })).toThrow("MCP_TOOL_QUARANTINED");
  });

  it("quarantines privilege drift and denies unknown tools", () => {
    expect(policy().inspect([
      { name: "search", inputSchema: schema, privilege: "write", approval: "allow-once" },
      { name: "shell", inputSchema: {}, privilege: "write", approval: "none" },
    ])).toEqual([
      { status: "quarantined", name: "search", reason: "privilege-drift" },
      { status: "denied", name: "shell", reason: "unknown-tool" },
    ]);
  });

  it("rejects duplicate or malformed server reports", () => {
    const exact = { name: "search", inputSchema: schema, privilege: "read" as const, approval: "none" as const };
    expect(() => policy().inspect([exact, exact])).toThrow("MCP_REPORTED_TOOL_DUPLICATE");
    expect(() => policy().inspect([{ ...exact, name: "../search" }])).toThrow("MCP_TOOL_NAME_INVALID");
  });
});
