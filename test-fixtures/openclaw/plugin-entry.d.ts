export interface OpenClawToolContext {
  readonly requesterSenderId?: string | null;
  readonly messageChannel?: string | null;
  readonly agentAccountId?: string | null;
  readonly agentId?: string | null;
}

export interface OpenClawPluginApi {
  readonly pluginConfig?: Record<string, unknown>;
  registerTool(
    tool:
      | Record<string, unknown>
      | ((toolContext: OpenClawToolContext) => unknown),
    options: { readonly name: string; readonly optional?: boolean },
  ): void;
  on(
    event: string,
    handler: (event: any, context: any) => unknown,
    options?: { readonly priority?: number },
  ): void;
}

export interface OpenClawPluginEntry {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly configSchema?: Record<string, unknown>;
  register(api: OpenClawPluginApi): void;
}

export function definePluginEntry(
  entry: OpenClawPluginEntry,
): OpenClawPluginEntry & { readonly configSchema: Record<string, unknown> };
