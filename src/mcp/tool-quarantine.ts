import { createHash } from "node:crypto";

export type McpToolPrivilege = "read" | "write";
export type McpToolApproval = "none" | "allow-once";

export type McpToolContract = {
  readonly name: string;
  readonly inputSchema: unknown;
  readonly privilege: McpToolPrivilege;
  readonly approval: McpToolApproval;
};

export type ApprovedMcpTool = {
  readonly name: string;
  readonly schemaSha256: string;
  readonly privilege: McpToolPrivilege;
  readonly approval: McpToolApproval;
};

export type McpToolDecision =
  | { readonly status: "allowed"; readonly name: string; readonly schemaSha256: string }
  | { readonly status: "quarantined"; readonly name: string; readonly reason: "schema-drift" | "privilege-drift" }
  | { readonly status: "denied"; readonly name: string; readonly reason: "unknown-tool" };

function canonical(value: unknown, depth = 0): string {
  if (depth > 24) throw new TypeError("MCP_SCHEMA_INVALID");
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item, depth + 1)).join(",")}]`;
  if (typeof value !== "object") throw new TypeError("MCP_SCHEMA_INVALID");
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new TypeError("MCP_SCHEMA_INVALID");
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key], depth + 1)}`).join(",")}}`;
}

function validateToolName(value: string): string {
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value)) throw new TypeError("MCP_TOOL_NAME_INVALID");
  return value;
}

export function mcpSchemaFingerprint(inputSchema: unknown): string {
  return createHash("sha256").update(canonical(inputSchema), "utf8").digest("hex");
}

/**
 * Compares a server-reported tool surface with a deployment-owned allowlist.
 * A tool is executable only when its name, schema, privilege, and approval
 * classification all match. Drift never updates the approved policy.
 */
export class McpToolQuarantine {
  readonly #approved: ReadonlyMap<string, ApprovedMcpTool>;

  constructor(approved: readonly ApprovedMcpTool[]) {
    const entries = new Map<string, ApprovedMcpTool>();
    for (const tool of approved) {
      const name = validateToolName(tool.name);
      if (entries.has(name) || !/^[a-f0-9]{64}$/u.test(tool.schemaSha256)) {
        throw new TypeError("MCP_APPROVED_TOOL_INVALID");
      }
      entries.set(name, Object.freeze({ ...tool, name }));
    }
    this.#approved = entries;
  }

  inspect(reported: readonly McpToolContract[]): readonly McpToolDecision[] {
    const seen = new Set<string>();
    const decisions: McpToolDecision[] = [];
    for (const tool of reported) {
      const name = validateToolName(tool.name);
      if (seen.has(name)) throw new TypeError("MCP_REPORTED_TOOL_DUPLICATE");
      seen.add(name);
      const approved = this.#approved.get(name);
      if (!approved) {
        decisions.push(Object.freeze({ status: "denied", name, reason: "unknown-tool" }));
        continue;
      }
      const schemaSha256 = mcpSchemaFingerprint(tool.inputSchema);
      if (schemaSha256 !== approved.schemaSha256) {
        decisions.push(Object.freeze({ status: "quarantined", name, reason: "schema-drift" }));
        continue;
      }
      if (tool.privilege !== approved.privilege || tool.approval !== approved.approval) {
        decisions.push(Object.freeze({ status: "quarantined", name, reason: "privilege-drift" }));
        continue;
      }
      decisions.push(Object.freeze({ status: "allowed", name, schemaSha256 }));
    }
    return Object.freeze(decisions);
  }

  requireAllowed(reported: McpToolContract): void {
    const [decision] = this.inspect([reported]);
    if (!decision || decision.status !== "allowed") throw new Error("MCP_TOOL_QUARANTINED");
  }
}
