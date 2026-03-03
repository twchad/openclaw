import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin, { registerGuardPlugin } from "./index.js";

describe("guard plugin", () => {
  const hooks: Record<string, Function> = {};
  const tools: Array<{ name: string }> = [];
  const httpRoutes: Array<{ path: string }> = [];
  const gatewayMethods: Array<string> = [];
  const commands: Array<{ name: string }> = [];

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
    registerHttpRoute: vi.fn((params: { path: string }) => httpRoutes.push({ path: params.path })),
    registerGatewayMethod: vi.fn((method: string) => gatewayMethods.push(method)),
    registerCommand: vi.fn((cmd: { name: string }) => commands.push({ name: cmd.name })),
    on: vi.fn((hookName: string, handler: Function) => {
      hooks[hookName] = handler;
    }),
  };

  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
    tools.length = 0;
    httpRoutes.length = 0;
    gatewayMethods.length = 0;
    commands.length = 0;
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

  it("registers hooks, tools, http routes, gateway methods and commands", () => {
    registerGuardPlugin(api as any);
    expect(api.on).toHaveBeenCalledWith("before_tool_call", expect.any(Function));
    expect(api.on).toHaveBeenCalledWith("message_sending", expect.any(Function));
    expect(api.on).toHaveBeenCalledWith("gateway_start", expect.any(Function));
    expect(httpRoutes.map((r) => r.path)).toContain("/guard/holds/:holdId/approve");
    expect(gatewayMethods).toContain("guard.hold.resolve");
    expect(commands.map((c) => c.name)).toContain("guard-approve");
  });

  it("blocks before_tool_call when guard denies without a hold", async () => {
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

  it("suspends and allows when guard returns a holdId and human approves", async () => {
    plugin.register(api as any);

    // Guard returns pendingApproval with holdId
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          authorized: false,
          holdId: "hold_test123",
          violations: [{ reason: "Approval required." }],
          remediation: { message: "Awaiting human approval." },
        }),
        { status: 200 },
      ),
    );

    // Simulate human approving after a short delay
    const resultPromise = hooks.before_tool_call(
      { toolName: "bash", params: { command: "rm important.txt" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );

    // Give the hook time to register the promise
    await new Promise((r) => setTimeout(r, 10));

    // Simulate the HTTP callback arriving (human approved via Guard UI)
    // The HTTP route handler would resolve holdPromises["hold_test123"]
    // We test this indirectly by triggering guard.hold.resolve gateway method
    const gatewayResolveHandler = api.registerGatewayMethod.mock.calls.find(
      ([method]) => method === "guard.hold.resolve",
    )?.[1];

    if (gatewayResolveHandler) {
      await gatewayResolveHandler({
        params: { holdId: "hold_test123", decision: "allow", resolvedBy: "test-human" },
        respond: vi.fn(),
        context: {
          broadcast: vi.fn(),
        },
      });
    }

    const result = await resultPromise;
    expect(result).toBeUndefined(); // allowed
  });
});
