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
    resolvePluginToolsMock.mockImplementation(() => [
      ...mockFullGuardToolSurface(),
      makeResolvedTool("file_fetch"),
    ]);
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
    const manager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517");
    const runAgent = vi.fn(async (_params: Record<string, unknown>) => ({
      payloads: [{ text: "ok" }],
    }));
    (manager as unknown as { runAgent: typeof runAgent }).runAgent = runAgent;

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

    const expectedGuardNames = mockFullGuardToolSurface().map((tool) => tool.name);
    expect(runAgent).toHaveBeenCalledWith(
      expect.objectContaining({
        toolsAllow: expect.arrayContaining(expectedGuardNames),
        bypassAgentToolPolicy: true,
        pluginToolAllowlistExtras: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
      }),
    );
    const runParams = runAgent.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(runParams.sessionId).toBe(sessionId);
    expect(String(runParams.sessionKey)).toContain(sessionId);
    expect(runParams.sandboxSessionKey).toBe(runParams.sessionKey);
    const toolsAllow = runParams.toolsAllow as string[];
    expect(toolsAllow.some((name) => !name.startsWith("guard_"))).toBe(true);
    expect(toolsAllow).toContain("exec");
    expect(toolsAllow).toContain("web_search");
    expect(toolsAllow).toContain("apply_patch");
    expect(toolsAllow).toContain("file_fetch");
    expect(runAgent.mock.calls[0]?.[0]).not.toHaveProperty("clientTools");
    manager.dispose();
  });

  it("derives introspection context and scopes create-mode scheme access by session ownership", async () => {
    const manager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517");

    const create = await manager.startSession({ mode: "create" });
    const createKey = `agent:test:${create.sessionId}`;
    const deferredToolManager = new AuthoringSessionManager(api as never, "http://127.0.0.1:4517");

    expect(manager.introspectionContextForSessionKey(undefined)).toBe("generic");
    expect(
      manager.introspectionContextForSessionKey(undefined, undefined, undefined, {
        allowSoleSessionFallback: true,
      }),
    ).toBe("new_scheme");
    expect(manager.introspectionContextForSessionKey(createKey)).toBe("new_scheme");
    expect(
      manager.introspectionContextForSessionKey(
        "agent:test:sandbox-session-key",
        undefined,
        create.sessionId,
      ),
    ).toBe("new_scheme");
    expect(
      deferredToolManager.introspectionContextForSessionKey(undefined, undefined, create.sessionId),
    ).toBe("new_scheme");
    expect(
      deferredToolManager.ensurePermittedSchemeTarget(undefined, {}, "read", create.sessionId, {
        requireSession: true,
      }),
    ).toMatchObject({
      ok: false,
      error: expect.stringContaining("ambient existing schemes"),
    });
    deferredToolManager.dispose();
    expect(manager.getSession(create.sessionId)).toBeDefined();
    expect(manager.ensurePermittedSchemeTarget(createKey, {}, "read")).toMatchObject({
      ok: false,
    });
    expect(
      manager.ensurePermittedSchemeTarget(undefined, {}, "read", undefined, {
        allowSoleSessionFallback: true,
        requireSession: true,
      }),
    ).toMatchObject({
      ok: false,
      error: expect.stringContaining("ambient existing schemes"),
    });
    expect(
      manager.ensurePermittedSchemeTarget("agent:test:missing-session", {}, "read", undefined, {
        requireSession: true,
      }),
    ).toMatchObject({
      ok: false,
      error: expect.stringContaining("No active Guard authoring session"),
    });
    expect(
      manager.ensurePermittedSchemeTarget(
        "agent:test:sandbox-session-key",
        {},
        "read",
        create.sessionId,
      ),
    ).toMatchObject({ ok: false });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { schemeId: "pre-existing" }, "read"),
    ).toMatchObject({ ok: false });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { intentId: "pre-existing-intent" }, "update"),
    ).toMatchObject({ ok: false });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { schemeId: "pre-existing" }, "expand"),
    ).toMatchObject({ ok: false });

    manager.recordOwnedSchemeForSessionKey(createKey, {
      schemeId: "scheme-1",
      intentId: "intent-1",
    });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { schemeId: "scheme-1" }, "read"),
    ).toEqual({ ok: true });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { intentId: "intent-1" }, "update"),
    ).toEqual({ ok: true });
    expect(
      manager.ensurePermittedSchemeTarget(
        "agent:test:sandbox-session-key",
        { schemeId: "scheme-1" },
        "read",
        create.sessionId,
      ),
    ).toEqual({ ok: true });
    manager.recordOwnedSchemeForSessionKey(undefined, { schemeId: "scheme-fallback" }, undefined, {
      allowSoleSessionFallback: true,
    });
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { schemeId: "scheme-fallback" }, "read"),
    ).toEqual({ ok: true });

    manager.recordOwnedSchemeForSessionKey(
      "agent:test:sandbox-session-key",
      {
        schemeId: "scheme-2",
      },
      create.sessionId,
    );
    expect(
      manager.ensurePermittedSchemeTarget(createKey, { schemeId: "scheme-2" }, "expand"),
    ).toEqual({ ok: true });

    const edit = await manager.startSession({ mode: "edit" });
    const editKey = `agent:test:${edit.sessionId}`;
    expect(manager.introspectionContextForSessionKey(editKey)).toBe("edit_existing");
    expect(manager.ensurePermittedSchemeTarget(editKey, {}, "read")).toEqual({ ok: true });

    const fpReview = await manager.startSession({ mode: "fp_review" });
    const fpReviewKey = `agent:test:${fpReview.sessionId}`;
    expect(manager.introspectionContextForSessionKey(fpReviewKey)).toBe("edit_existing");

    const fnReview = await manager.startSession({ mode: "fn_review" });
    const fnReviewKey = `agent:test:${fnReview.sessionId}`;
    expect(manager.introspectionContextForSessionKey(fnReviewKey)).toBe("edit_existing");

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
