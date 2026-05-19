import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN } from "./authoring-allowlist-token.js";
import {
  GUARD_AUTHORING_ONLY_TOOL_NAMES,
  GUARD_AUTHORING_RESOLVE_ALLOWLIST,
  GUARD_RUNTIME_TOOL_NAMES,
  MIN_GUARD_AUTHORING_SESSION_TOOL_COUNT,
} from "./authoring-tools-contract.js";
import { AuthoringSessionManager } from "./authoring.js";

const resolvePluginToolsMock = vi.fn();
const resetPluginToolDescriptorCacheMock = vi.fn();

vi.mock("../../../src/plugins/tools.js", () => ({
  resolvePluginTools: (...args: unknown[]) => resolvePluginToolsMock(...args),
  resetPluginToolDescriptorCache: () => resetPluginToolDescriptorCacheMock(),
}));

function makeResolvedTool(name: string) {
  return {
    name,
    description: `${name} tool`,
    parameters: { type: "object", properties: {} },
    async execute() {
      return { content: [{ type: "text", text: "ok" }] };
    },
  };
}

function mockFullGuardToolSurface() {
  return [...GUARD_RUNTIME_TOOL_NAMES, ...GUARD_AUTHORING_ONLY_TOOL_NAMES].map((name) =>
    makeResolvedTool(name),
  );
}

describe("guard authoring tool surface regressions", () => {
  const api = {
    config: { agents: { defaults: { workspace: "/tmp/workspace" } } },
    logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    resetPluginToolDescriptorCacheMock.mockClear();
    resolvePluginToolsMock.mockImplementation(() => mockFullGuardToolSurface());
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({}),
    })) as unknown as typeof globalThis.fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("startSession clears the plugin tool cache and resolves with the authoring allowlist", async () => {
    const manager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517");

    const result = await manager.startSession({ mode: "create" });

    expect(resetPluginToolDescriptorCacheMock).toHaveBeenCalled();
    expect(resolvePluginToolsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        toolAllowlist: [...GUARD_AUTHORING_RESOLVE_ALLOWLIST],
        suppressNameConflicts: true,
      }),
    );
    expect(api.logger.info).toHaveBeenCalledWith(
      expect.stringContaining(`guard_tools_available=${MIN_GUARD_AUTHORING_SESSION_TOOL_COUNT}`),
    );
    expect(api.logger.info).toHaveBeenCalledWith(expect.stringContaining("guard_introspect"));
    expect(result.sessionId).toMatch(/^guard-authoring-/);
    manager.dispose();
  });

  it("sendMessage re-resolves guard_* tools and pins toolsAllow on every turn", async () => {
    const manager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517") as never;
    const runAgent = vi.fn(async () => ({ payloads: [{ text: "ok" }] }));
    manager.runAgent = runAgent;

    const { sessionId } = await manager.startSession({ mode: "create" });

    resetPluginToolDescriptorCacheMock.mockClear();
    resolvePluginToolsMock.mockClear();

    await manager.sendMessage(sessionId, "List your guard tools", () => {});

    expect(resetPluginToolDescriptorCacheMock).toHaveBeenCalled();
    expect(resolvePluginToolsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        toolAllowlist: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
      }),
    );

    const expectedNames = mockFullGuardToolSurface().map((tool) => tool.name);
    expect(runAgent).toHaveBeenCalledWith(
      expect.objectContaining({
        toolsAllow: expectedNames,
        bypassAgentToolPolicy: true,
        pluginToolAllowlistExtras: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
      }),
    );
    manager.dispose();
  });

  it("fails fast when authoring resolves zero guard_* tools", async () => {
    resolvePluginToolsMock.mockReturnValue([]);
    const manager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517");

    await expect(manager.startSession({ mode: "create" })).rejects.toThrow(
      /no guard_\* tools resolved/i,
    );
    manager.dispose();
  });
});
