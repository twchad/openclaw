import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin, { registerGuardPlugin } from "./index.js";

describe("guard plugin", () => {
  const hooks: Record<string, Function> = {};
  const tools: Array<{ name: string }> = [];
  const api = {
    pluginConfig: {
      endpoint: "http://127.0.0.1:4517",
      timeoutMs: 50,
      failurePolicy: "fail_open",
    },
    config: {},
    id: "guard",
    name: "Guard",
    logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
    registerTool: vi.fn((tool: { name: string }) => tools.push({ name: tool.name })),
    on: vi.fn((hookName: string, handler: Function) => {
      hooks[hookName] = handler;
    }),
  };

  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
    tools.length = 0;
    for (const key of Object.keys(hooks)) {
      delete hooks[key];
    }
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn() as unknown as typeof globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("registers hooks and graph tools", () => {
    registerGuardPlugin(api as any);
    expect(api.on).toHaveBeenCalledWith("before_tool_call", expect.any(Function));
    expect(api.on).toHaveBeenCalledWith("message_sending", expect.any(Function));
    expect(tools.map((t) => t.name).sort()).toEqual(["guard_graph_compose", "guard_graph_read"]);
  });

  it("blocks before_tool_call when guard denies", async () => {
    plugin.register(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          authorized: false,
          violations: [{ reason: "Destructive action pattern detected." }],
          remediation: { message: "Use explicit approval." },
        }),
        { status: 200 },
      ),
    );

    const result = await hooks.before_tool_call(
      { toolName: "bash", params: { command: "rm -rf /" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );
    expect(result).toEqual({
      block: true,
      blockReason: "Destructive action pattern detected. Use explicit approval.",
    });
  });

  it("rewrites outbound content when output is denied", async () => {
    plugin.register(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          authorized: false,
          violations: [{ reason: "Generated output appears to include destructive behavior." }],
          remediation: { message: "Adjust your plan." },
        }),
        { status: 200 },
      ),
    );

    const result = await hooks.message_sending(
      { to: "u1", content: "Here is a script:\nrm -rf /", metadata: {} },
      { channelId: "chat", conversationId: "s1" },
    );
    expect(result).toEqual({
      content:
        "Guard blocked message output. Generated output appears to include destructive behavior. Adjust your plan.",
    });
  });

  it("fails open when sidecar is unavailable and fail_open active", async () => {
    plugin.register(api as any);
    vi.mocked(globalThis.fetch).mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await hooks.before_tool_call(
      { toolName: "bash", params: { command: "echo hi" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );
    expect(result).toBeUndefined();
    expect(api.logger.warn).toHaveBeenCalledWith(expect.stringContaining("fail-open"));
  });
});
