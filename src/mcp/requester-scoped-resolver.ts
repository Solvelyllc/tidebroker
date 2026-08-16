import {
  trustedActorFromHostContext,
  type TrustedActorId,
} from "../core/identity.js";
import type { McpToolContract, McpToolQuarantine } from "./tool-quarantine.js";

export type RequesterScopedMcpContext = {
  requesterSenderId: string;
  agentAccountId?: string;
  messageChannel?: string;
};

export type RequesterScopedMcpConnection = {
  url: string;
  headers?: Record<string, string>;
};

export type RequesterScopedMcpBindingRequest = {
  actorId: TrustedActorId;
  serverName: string;
  agentAccountId?: string;
  messageChannel?: string;
};

export interface RequesterScopedMcpBindingProvider {
  resolve(
    request: RequesterScopedMcpBindingRequest,
  ): Promise<RequesterScopedMcpConnection | null> | RequesterScopedMcpConnection | null;
}

export type RequesterScopedMcpResolver = {
  serverName: string;
  resolve(
    context: RequesterScopedMcpContext,
  ): Promise<RequesterScopedMcpConnection | null>;
};

export type RequesterScopedMcpToolProbe = (
  connection: Readonly<RequesterScopedMcpConnection>,
) => Promise<readonly McpToolContract[]>;

const FORBIDDEN_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function validateServerName(value: string): string {
  const normalized = value.trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(normalized)) {
    throw new Error("MCP server name must be a stable lowercase identifier");
  }
  return normalized;
}

function validateConnection(connection: RequesterScopedMcpConnection): RequesterScopedMcpConnection {
  let url: URL;
  try {
    url = new URL(connection.url);
  } catch {
    throw new Error("Requester-scoped MCP resolver returned an invalid URL");
  }

  const isHttps = url.protocol === "https:";
  const isLoopbackHttp =
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1");
  if (!isHttps && !isLoopbackHttp) {
    throw new Error("Requester-scoped MCP connections require HTTPS or loopback HTTP");
  }
  if (url.username || url.password) {
    throw new Error("Requester-scoped MCP credentials must not be embedded in URLs");
  }

  const headers: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(connection.headers ?? {})) {
    const name = rawName.trim().toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(name) || FORBIDDEN_HEADERS.has(name)) {
      throw new Error(`Requester-scoped MCP header is not allowed: ${rawName}`);
    }
    if (/\r|\n|\0/u.test(rawValue)) {
      throw new Error(`Requester-scoped MCP header contains invalid characters: ${rawName}`);
    }
    headers[name] = rawValue;
  }

  return {
    url: url.toString(),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  };
}

/**
 * Adapt a deployment-owned binding provider to OpenClaw's requester-scoped MCP
 * resolver contract. Actor identity always comes from host runtime context.
 */
export function createRequesterScopedMcpResolver(params: {
  serverName: string;
  bindings: RequesterScopedMcpBindingProvider;
}): RequesterScopedMcpResolver {
  const serverName = validateServerName(params.serverName);
  return {
    serverName,
    async resolve(context) {
      const actor = trustedActorFromHostContext(context);
      if (!actor.ok) {
        return null;
      }
      const resolved = await params.bindings.resolve({
        actorId: actor.actorId,
        serverName,
        ...(context.agentAccountId ? { agentAccountId: context.agentAccountId } : {}),
        ...(context.messageChannel ? { messageChannel: context.messageChannel } : {}),
      });
      return resolved ? validateConnection(resolved) : null;
    },
  };
}

/**
 * Resolves a requester-bound transport, probes its live tool surface, and
 * returns the connection only when every reported tool exactly matches the
 * deployment-owned policy. Unknown or drifted tools quarantine the server for
 * the current resolution instead of leaking a partial unsafe surface.
 */
export function createQuarantinedRequesterScopedMcpResolver(params: {
  serverName: string;
  bindings: RequesterScopedMcpBindingProvider;
  quarantine: McpToolQuarantine;
  probe: RequesterScopedMcpToolProbe;
}): RequesterScopedMcpResolver {
  const resolver = createRequesterScopedMcpResolver(params);
  return {
    serverName: resolver.serverName,
    async resolve(context) {
      const connection = await resolver.resolve(context);
      if (!connection) return null;
      const reported = await params.probe(connection);
      const decisions = params.quarantine.inspect(reported);
      return decisions.length > 0 && decisions.every((decision) => decision.status === "allowed")
        ? connection
        : null;
    },
  };
}
