import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin, { registerGuardPlugin } from "./index.js";
import { clearGuardAuthCacheForTests } from "./src/auth.js";
import { GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN } from "./src/authoring-allowlist-token.js";
import {
  GUARD_AUTHORING_ONLY_TOOL_NAMES,
  GUARD_RUNTIME_TOOL_NAMES,
} from "./src/authoring-tools-contract.js";
import {
  AuthoringSessionManager,
  buildAuthoringSystemPrompt,
  cleanupExpiredGuardSignatureCaptureRuns,
  registerAuthoringGateway,
  registerAuthoringHttpHandler,
  registerGuardSignatureCaptureRun,
} from "./src/authoring.js";

type RegisteredTool = {
  name: string;
  opts?: Record<string, unknown>;
  tool: any;
};

describe("guard plugin", () => {
  const hooks: Record<string, Function> = {};
  const tools: RegisteredTool[] = [];
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
    registerTool: vi.fn((tool: { name?: string } | Function, opts?: Record<string, unknown>) => {
      const resolved =
        typeof tool === "function"
          ? tool({
              sessionKey: "agent:test:guard-authoring-session-1",
              sessionId: "guard-authoring-session-1",
            })
          : tool;
      tools.push({ name: resolved.name ?? "", opts, tool: resolved });
    }),
    registerGatewayMethod: vi.fn(),
    registerHttpRoute: vi.fn(),
    registerCommand: vi.fn(),
    on: vi.fn((hookName: string, handler: Function) => {
      hooks[hookName] = handler;
    }),
  };

  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
    cleanupExpiredGuardSignatureCaptureRuns(Number.POSITIVE_INFINITY);
    tools.length = 0;
    for (const key of Object.keys(hooks)) {
      delete hooks[key];
    }
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn() as unknown as typeof globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    clearGuardAuthCacheForTests();
    vi.restoreAllMocks();
  });

  async function writeGuardCredential(apiKey: string) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "guard-credential-"));
    const credentialFile = path.join(dir, "openclaw-client.json");
    await fs.writeFile(
      credentialFile,
      JSON.stringify({
        version: 1,
        endpoint: "http://127.0.0.1:4517",
        header: "X-Guard-API-Key",
        apiKey,
        createdAt: "2026-05-29T19:00:00Z",
        pid: 12345,
      }),
      "utf8",
    );
    return credentialFile;
  }

  function withCredentialFile(credentialFile: string) {
    return {
      ...api,
      pluginConfig: {
        ...api.pluginConfig,
        credentialFile,
      },
    };
  }

  function parseJsonRequestBody(body: RequestInit["body"]): any {
    if (typeof body !== "string") {
      throw new TypeError("Expected mocked fetch body to be a JSON string.");
    }
    return JSON.parse(body);
  }

  it("registers hooks and keeps runtime and authoring tools separated", () => {
    registerGuardPlugin(api as any);
    expect(api.on).toHaveBeenCalledWith("before_tool_call", expect.any(Function));
    expect(api.on).toHaveBeenCalledWith("message_sending", expect.any(Function));

    for (const name of GUARD_RUNTIME_TOOL_NAMES) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, `missing runtime tool registration: ${name}`).toBeDefined();
      expect(tool?.opts).toMatchObject({ optional: true });
      if (tool?.opts?.name) {
        expect(tool.opts.name).toBe(name);
      }
      expect(tool?.opts?.optionalRequiresAllowlistToken).toBeUndefined();
    }

    for (const name of GUARD_AUTHORING_ONLY_TOOL_NAMES) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, `missing authoring tool registration: ${name}`).toBeDefined();
      expect(tool?.opts).toMatchObject({
        optional: true,
        optionalRequiresAllowlistToken: GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN,
      });
      if (tool?.opts?.name) {
        expect(tool.opts.name).toBe(name);
      }
    }
  });

  it("defaults guard_introspect to generic without an authoring session and forwards explicit context", async () => {
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ authoringGuide: { workflow: [] } }), { status: 200 }),
    );

    const introspect = tools.find((t) => t.name === "guard_introspect")?.tool;
    await introspect.execute("introspect-1", {});
    await introspect.execute("introspect-2", { context: "new_scheme" });

    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[0]).toBe(
      "http://127.0.0.1:4517/v1/rules/spec?context=generic",
    );
    expect(vi.mocked(globalThis.fetch).mock.calls[1]?.[0]).toBe(
      "http://127.0.0.1:4517/v1/rules/spec?context=new_scheme",
    );
  });

  it("attaches the handoff API key to guard tool requests", async () => {
    const credentialFile = await writeGuardCredential("handoff-key");
    registerGuardPlugin(withCredentialFile(credentialFile) as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ authoringGuide: { workflow: [] } }), { status: 200 }),
    );

    const introspect = tools.find((t) => t.name === "guard_introspect")?.tool;
    await introspect.execute("introspect-1", {});

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect((init as RequestInit).headers).toMatchObject({
      "X-Guard-API-Key": "handoff-key",
    });
  });

  it("reloads the handoff credential and retries once after a 401", async () => {
    const credentialFile = await writeGuardCredential("old-key");
    registerGuardPlugin(withCredentialFile(credentialFile) as any);
    vi.mocked(globalThis.fetch)
      .mockImplementationOnce(async () => {
        await fs.writeFile(
          credentialFile,
          JSON.stringify({
            version: 1,
            endpoint: "http://127.0.0.1:4517",
            header: "X-Guard-API-Key",
            apiKey: "new-key",
            createdAt: "2026-05-29T19:01:00Z",
            pid: 12346,
          }),
          "utf8",
        );
        return new Response(JSON.stringify({ error: "bad key" }), { status: 401 });
      })
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ authoringGuide: { workflow: [] } }), { status: 200 }),
      );

    const introspect = tools.find((t) => t.name === "guard_introspect")?.tool;
    const result = await introspect.execute("introspect-1", {});

    expect(result.details).toMatchObject({ ok: true });
    expect(vi.mocked(globalThis.fetch)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.headers).toMatchObject({
      "X-Guard-API-Key": "old-key",
    });
    expect(vi.mocked(globalThis.fetch).mock.calls[1]?.[1]?.headers).toMatchObject({
      "X-Guard-API-Key": "new-key",
    });
  });

  it("returns a clear guard tool error when auth is required but no handoff exists", async () => {
    const credentialFile = path.join(os.tmpdir(), `missing-guard-credential-${Date.now()}.json`);
    registerGuardPlugin(withCredentialFile(credentialFile) as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ error: "guard API authentication required" }), {
        status: 401,
      }),
    );

    const introspect = tools.find((t) => t.name === "guard_introspect")?.tool;
    const result = await introspect.execute("introspect-1", {});

    expect(result.details).toMatchObject({
      ok: false,
      error: expect.stringContaining("Guard API authentication failed"),
    });
    expect(result.details.error).toContain(credentialFile);
  });

  it("attaches the handoff API key to hold status and command approval requests", async () => {
    const credentialFile = await writeGuardCredential("hold-key");
    registerGuardPlugin(withCredentialFile(credentialFile) as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ holdId: "hold-1", status: "pending" }), { status: 200 }),
    );

    const holdStatus = tools.find((t) => t.name === "guard_hold_status")?.tool;
    await holdStatus.execute("hold-status-1", { holdId: "hold-1" });

    const command = vi.mocked(api.registerCommand).mock.calls[0]?.[0] as {
      handler: (ctx: { args?: string; userId?: string }) => Promise<{ text: string }>;
    };
    await command.handler({ args: "hold-1 allow", userId: "test-user" });

    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.headers).toMatchObject({
      "X-Guard-API-Key": "hold-key",
    });
    expect(vi.mocked(globalThis.fetch).mock.calls[1]?.[1]?.headers).toMatchObject({
      "X-Guard-API-Key": "hold-key",
    });
  });

  it("attaches the handoff API key to decision hook requests", async () => {
    const credentialFile = await writeGuardCredential("decision-key");
    plugin.register(withCredentialFile(credentialFile) as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ authorized: true }), { status: 200 }),
    );

    await hooks.before_tool_call(
      { toolName: "bash", params: { command: "date" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );

    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.headers).toMatchObject({
      "X-Guard-API-Key": "decision-key",
    });
  });

  it("attaches the handoff API key to authoring manager Guard fetches", async () => {
    const credentialFile = await writeGuardCredential("authoring-key");
    const manager = new AuthoringSessionManager(
      api as any,
      "http://127.0.0.1:4517",
      credentialFile,
    ) as any;
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ schemeId: "scheme-1" }), { status: 200 }),
    );

    await manager.guardFetch("/v1/authoring/scheme", "GET", undefined, {
      "X-Guard-Role": "author",
    });

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect((init as RequestInit).headers).toMatchObject({
      "X-Guard-Role": "author",
      "X-Guard-API-Key": "authoring-key",
    });
    manager.dispose();
  });

  it("passes tool sessionId into authoring scheme boundary checks", async () => {
    const accessSpy = vi.spyOn(AuthoringSessionManager.prototype, "ensurePermittedSchemeTarget");
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ schemeId: "scheme-1" }), { status: 200 }),
    );

    const readScheme = tools.find((t) => t.name === "guard_scheme_read")?.tool;
    await readScheme.execute("read", { schemeId: "scheme-1" });

    expect(accessSpy).toHaveBeenCalledWith(
      "agent:test:guard-authoring-session-1",
      { schemeId: "scheme-1" },
      "read",
      "guard-authoring-session-1",
      { allowSoleSessionFallback: true, requireSession: true },
    );
  });

  it("exposes scheme gate fields for simulation without knowledge-test answers", () => {
    registerGuardPlugin(api as any);

    const simulate = tools.find((t) => t.name === "guard_simulate")?.tool;
    const props = simulate.parameters.properties;

    expect(props).toHaveProperty("approvalRequired");
    expect(props).toHaveProperty("approvalWindowSeconds");
    expect(props).toHaveProperty("knowledgeTest");
    expect(props).toHaveProperty("exceptions");
    expect(props).toHaveProperty("nearMissPolicy");
    expect(props).not.toHaveProperty("knowledgeTestAnswers");
    expect(props.rules.items.properties.syntax.properties).toHaveProperty("denyPattern");
    expect(props.rules.items.properties.syntax.additionalProperties).toBe(true);
    expect(props.rules.items.properties.semantics.properties).toHaveProperty("elaborations");
    expect(props.rules.items.properties.semantics.additionalProperties).toBe(true);
    expect(props.events.items.properties.identity.properties).toHaveProperty("sessionKey");
    expect(props.events.items.properties.action.properties.args.additionalProperties).toBe(true);
    expect(simulate.parameters.additionalProperties).toBe(true);

    const compile = tools.find((t) => t.name === "guard_compile_scheme")?.tool;
    expect(compile.parameters.properties).toHaveProperty("knowledgeTest");
  });

  it("forwards simulate gate fields but not knowledge-test answers", async () => {
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ results: [] }), { status: 200 }),
    );

    const simulate = tools.find((t) => t.name === "guard_simulate")?.tool;
    await simulate.execute("call-1", {
      rules: [
        {
          ruleId: "r1",
          ruleType: "SYNTAX",
          syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
        },
      ],
      events: [
        {
          eventType: "ACTION_EVENT",
          eventId: "e1",
          identity: { agentId: "test-agent", sessionKey: "session-1" },
          action: { toolName: "exec", args: { command: "claude" } },
        },
      ],
      approvalRequired: true,
      approvalWindowSeconds: 30,
      knowledgeTest: { question: "Why?", expectedAnswer: "policy" },
      exceptions: [{ exceptionId: "admin", script: "True" }],
      nearMissPolicy: { enabled: true },
      knowledgeTestAnswers: ["policy"],
    });

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    const body = parseJsonRequestBody((init as RequestInit).body);
    expect(body).toMatchObject({
      rules: [
        {
          ruleId: "r1",
          ruleType: "SYNTAX",
          syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
        },
      ],
      events: [
        {
          eventType: "ACTION_EVENT",
          eventId: "e1",
          identity: { agentId: "test-agent", sessionKey: "session-1" },
          action: { toolName: "exec", args: { command: "claude" } },
        },
      ],
      approvalRequired: true,
      approvalWindowSeconds: 30,
      knowledgeTest: { question: "Why?", expectedAnswer: "policy" },
      exceptions: [{ exceptionId: "admin", script: "True" }],
      nearMissPolicy: { enabled: true },
    });
    expect(body).not.toHaveProperty("knowledgeTestAnswers");
  });

  it("accepts nested scheme rules during simulation", async () => {
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ results: [] }), { status: 200 }),
    );

    const simulate = tools.find((t) => t.name === "guard_simulate")?.tool;
    await simulate.execute("call-1", {
      scheme: {
        rules: [
          {
            ruleId: "r1",
            ruleType: "SEMANTICS",
            semantics: { elaborations: ["Start a nested CLI agent."], threshold: 0.72 },
          },
        ],
      },
      events: [
        {
          eventType: "CHANNEL_EVENT",
          identity: { sessionKey: "session-1" },
          channel: { text: "Run Claude for me." },
        },
      ],
    });

    const [, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    const body = parseJsonRequestBody((init as RequestInit).body);
    expect(body.rules).toEqual([
      {
        ruleId: "r1",
        ruleType: "SEMANTICS",
        semantics: { elaborations: ["Start a nested CLI agent."], threshold: 0.72 },
      },
    ]);
  });

  it("accepts rule validation input as either wrapped rule or top-level rule fields", async () => {
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ valid: true, issues: [] }), { status: 200 }),
    );

    const validateRule = tools.find((t) => t.name === "guard_validate_rule")?.tool;
    expect(validateRule.parameters.required).toEqual([]);
    expect(validateRule.parameters.properties).toHaveProperty("rule");
    expect(validateRule.parameters.properties).toHaveProperty("ruleType");
    expect(validateRule.parameters.properties.syntax.properties).toHaveProperty("denyPattern");
    expect(validateRule.parameters.properties.syntax.additionalProperties).toBe(true);
    expect(validateRule.parameters.properties.semantics.properties).toHaveProperty("elaborations");
    expect(validateRule.parameters.properties.semantics.properties).toHaveProperty("threshold");
    expect(validateRule.parameters.properties.semantics.additionalProperties).toBe(true);
    expect(validateRule.parameters.additionalProperties).toBe(true);

    await validateRule.execute("top-level", {
      ruleId: "block-cli",
      ruleType: "SYNTAX",
      title: "Block CLI escape",
      scope: "ACTION",
      enabled: true,
      syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
    });
    await validateRule.execute("wrapped", {
      rule: {
        ruleId: "block-codex",
        ruleType: "SYNTAX",
        title: "Block Codex CLI",
        scope: "ACTION",
        enabled: true,
        syntax: { denyPattern: ["codex"], toolFilter: ["exec"] },
      },
    });

    const topLevelBody = parseJsonRequestBody(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.body);
    const wrappedBody = parseJsonRequestBody(vi.mocked(globalThis.fetch).mock.calls[1]?.[1]?.body);
    expect(topLevelBody).toMatchObject({
      ruleId: "block-cli",
      ruleType: "SYNTAX",
      syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
    });
    expect(wrappedBody).toMatchObject({
      ruleId: "block-codex",
      ruleType: "SYNTAX",
      syntax: { denyPattern: ["codex"], toolFilter: ["exec"] },
    });
  });

  it("accepts scheme-level fields during validation while forwarding only rules", async () => {
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ valid: true, issues: [] }), { status: 200 }),
    );

    const validateScheme = tools.find((t) => t.name === "guard_validate_scheme")?.tool;
    expect(validateScheme.parameters.properties).toHaveProperty("mode");
    expect(validateScheme.parameters.properties).toHaveProperty("approvalRequired");
    expect(validateScheme.parameters.properties).toHaveProperty("knowledgeTest");
    expect(
      validateScheme.parameters.properties.rules.items.properties.syntax.properties,
    ).toHaveProperty("denyPattern");
    expect(
      validateScheme.parameters.properties.rules.items.properties.semantics.properties,
    ).toHaveProperty("elaborations");
    expect(validateScheme.parameters.additionalProperties).toBe(true);

    await validateScheme.execute("scheme", {
      rules: [
        {
          ruleId: "r1",
          ruleType: "SYNTAX",
          syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
        },
      ],
      mode: "OBSERVE",
      approvalRequired: true,
      approvalWindowSeconds: 300,
      knowledgeTest: { question: "Why?", expectedAnswer: "policy" },
      exceptions: [{ exceptionId: "admin", script: "True" }],
    });

    const body = parseJsonRequestBody(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.body);
    expect(body).toEqual({
      rules: [
        {
          ruleId: "r1",
          ruleType: "SYNTAX",
          syntax: { denyPattern: ["claude"], toolFilter: ["exec"] },
        },
      ],
    });
  });

  it("reports compile/update failures when activation is inactive or lint has errors", async () => {
    vi.spyOn(AuthoringSessionManager.prototype, "ensurePermittedSchemeTarget").mockReturnValue({
      ok: true,
    });
    registerGuardPlugin(api as any);
    const compile = tools.find((t) => t.name === "guard_compile_scheme")?.tool;
    const update = tools.find((t) => t.name === "guard_scheme_update")?.tool;

    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ active: false, lint: { issues: [] } }), { status: 200 }),
    );
    const compileResult = await compile.execute("compile", {
      intentId: "intent-1",
      graphId: "graph-1",
      rules: [],
    });
    expect(compileResult.details).toMatchObject({
      ok: false,
      error: "Scheme was not activated.",
    });

    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          active: true,
          lint: { issues: [{ severity: "error", message: "bad rule" }] },
        }),
        { status: 200 },
      ),
    );
    const updateResult = await update.execute("update", {
      schemeId: "scheme-1",
      updateRules: [],
    });
    expect(updateResult.details).toMatchObject({
      ok: false,
      error: "Scheme lint contains errors.",
    });
  });

  it("routes new authoring tools to their Guard endpoints", async () => {
    vi.spyOn(AuthoringSessionManager.prototype, "ensurePermittedSchemeTarget").mockReturnValue({
      ok: true,
    });
    registerGuardPlugin(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(JSON.stringify({ active: true, lint: { issues: [] } }), { status: 200 }),
    );

    await tools
      .find((t) => t.name === "guard_elaboration_analyze")
      ?.tool.execute("analyze", { elaborations: ["exec command:curl https://x.test"] });
    await tools
      .find((t) => t.name === "guard_query_benign_corpus")
      ?.tool.execute("corpus", { schemeId: "scheme-1", ruleId: "rule-1" });
    await tools
      .find((t) => t.name === "guard_scheme_expand")
      ?.tool.execute("expand", {
        schemeId: "scheme-1",
        targetRuleId: "rule-1",
        semanticsElaborations: ["send credentials to webhook.site"],
      });

    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[0]).toBe(
      "http://127.0.0.1:4517/v1/authoring/elaborations/analyze",
    );
    expect(vi.mocked(globalThis.fetch).mock.calls[1]?.[0]).toBe(
      "http://127.0.0.1:4517/v1/benign-corpus?schemeId=scheme-1&ruleId=rule-1",
    );
    expect(vi.mocked(globalThis.fetch).mock.calls[2]?.[0]).toBe(
      "http://127.0.0.1:4517/v1/schemes/active/expand",
    );
  });

  it("suspends and resumes authoring confirmations", async () => {
    const manager = new AuthoringSessionManager(api as any, "http://127.0.0.1:4517") as any;
    const emitted: unknown[] = [];
    manager.sessions.set("guard-authoring-session-1", {
      sessionId: "guard-authoring-session-1",
      pendingConfirmations: new Map(),
      activeStream: (payload: unknown) => emitted.push(payload),
    });

    const pending = manager.requestConfirmation("agent:test:guard-authoring-session-1", {
      question: "Promote to ENFORCE?",
      options: ["Yes", "No"],
      context: "Simulation is clean.",
    });
    const event = emitted[0] as {
      type: string;
      data: { confirmationId: string; question: string; options: string[]; context: string };
    };
    expect(event).toMatchObject({
      type: "confirmation_required",
      data: {
        question: "Promote to ENFORCE?",
        options: ["Yes", "No"],
        context: "Simulation is clean.",
      },
    });

    expect(manager.confirm("guard-authoring-session-1", event.data.confirmationId, "No")).toBe(
      true,
    );
    await expect(pending).resolves.toEqual({ answer: "No" });
    manager.dispose();
  });

  it("falls back to the sole active authoring session when confirmation session key is stale", async () => {
    const manager = new AuthoringSessionManager(api as any, "http://127.0.0.1:4517") as any;
    const emitted: unknown[] = [];
    manager.sessions.set("guard-authoring-session-1", {
      sessionId: "guard-authoring-session-1",
      pendingConfirmations: new Map(),
      activeStream: (payload: unknown) => emitted.push(payload),
    });

    const pending = manager.requestConfirmation("agent:test:stale-session-key", {
      question: "Use broad exception?",
    });
    const event = emitted[0] as { data: { confirmationId: string } };

    expect(manager.confirm("guard-authoring-session-1", event.data.confirmationId, "No")).toBe(
      true,
    );
    await expect(pending).resolves.toEqual({ answer: "No" });
    manager.dispose();
  });

  it("runs one authoring agent turn without forced no-tool retries", async () => {
    const manager = new AuthoringSessionManager(api as any, "http://127.0.0.1:4517") as any;
    const text = "I can repair the Claude/Codex CLI rule if you want.";
    const runAgent = vi.fn(async (_params: Record<string, unknown>) => ({ payloads: [{ text }] }));
    manager.runAgent = runAgent;
    manager.sessions.set("guard-authoring-session-1", {
      sessionId: "guard-authoring-session-1",
      mode: "edit",
      intentId: "intent-claude-codex",
      graphId: "graph-claude-codex",
      tempDir: "/tmp",
      sessionFile: "/tmp/guard-authoring-session.json",
      toolCatalog: "exec: run commands",
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      guardToolNames: ["guard_introspect", "guard_graph_read", "guard_compile_scheme"],
      guardedToolNames: ["exec"],
      guardedToolEntries: [
        {
          name: "exec",
          section: "Runtime",
          description: "Run a command",
          parameters: { type: "object", properties: { command: { type: "string" } } },
        },
      ],
      ownedSchemeIds: new Set(),
      ownedIntentIds: new Set(),
      pendingConfirmations: new Map(),
    });

    const events: unknown[] = [];
    const result = await manager.sendMessage(
      "guard-authoring-session-1",
      "Can you fix the Claude/Codex CLI rule?",
      (payload: unknown) => events.push(payload),
    );

    expect(runAgent).toHaveBeenCalledTimes(1);
    expect(runAgent.mock.calls[0]?.[0]).toMatchObject({
      prompt: "Can you fix the Claude/Codex CLI rule?",
      toolsAllow: ["guard_introspect", "guard_graph_read", "guard_compile_scheme", "exec"],
      bypassAgentToolPolicy: true,
    });
    expect(runAgent.mock.calls[0]?.[0]).not.toHaveProperty("clientTools");
    expect(result).toEqual({ text });
    expect(events).toContainEqual({ type: "done", data: { text } });
    expect(events).not.toContainEqual(expect.objectContaining({ type: "error" }));
    manager.dispose();
  });

  it("keeps create mode and edit mode prompt contexts distinct", () => {
    const createPrompt = buildAuthoringSystemPrompt({
      mode: "create",
      toolCatalog: "exec: run commands",
    });
    expect(createPrompt).toContain("## New Scheme (Create Mode)");
    expect(createPrompt).toContain("creating a new Guard scheme from scratch");
    expect(createPrompt).toContain("call that tool with harmless-shaped arguments");
    expect(createPrompt).toContain("use tool_search/tool_describe/tool_call");
    expect(createPrompt).not.toContain("ONLY use guard_* tools");
    expect(createPrompt).not.toContain("## Edit Existing Scheme Mode");

    const editWithSchemePrompt = buildAuthoringSystemPrompt({
      mode: "edit",
      intentId: "intent-1",
      graphId: "graph-1",
      scheme: { schemeId: "scheme-1", rules: [{ ruleId: "rule-1" }] },
      toolCatalog: "exec: run commands",
    });
    expect(editWithSchemePrompt).toContain("## Edit Existing Scheme Mode");
    expect(editWithSchemePrompt).toContain("intentId: `intent-1`");
    expect(editWithSchemePrompt).toContain("graphId: `graph-1`");
    expect(editWithSchemePrompt).toContain("### Current Active Scheme");
    expect(editWithSchemePrompt).not.toContain("## New Scheme (Create Mode)");

    const editWithoutSchemePrompt = buildAuthoringSystemPrompt({
      mode: "edit",
      intentId: "intent-1",
      graphId: "graph-1",
      toolCatalog: "exec: run commands",
    });
    expect(editWithoutSchemePrompt).toContain("## Edit Existing Scheme Mode");
    expect(editWithoutSchemePrompt).toContain("No active scheme was returned");
    expect(editWithoutSchemePrompt).toContain("create the missing initial scheme");
    expect(editWithoutSchemePrompt).not.toContain("## New Scheme (Create Mode)");
  });

  it("preserves fp_review and fn_review context when starting through the gateway", async () => {
    const methods: Record<string, Function> = {};
    const gatewayApi = {
      registerGatewayMethod: vi.fn((name: string, handler: Function) => {
        methods[name] = handler;
      }),
    };
    const manager = {
      startSession: vi.fn(async (params) => ({ sessionId: "s1", mode: params.mode })),
    };
    registerAuthoringGateway(gatewayApi as any, manager as any);

    const fpRespond = vi.fn();
    await methods["guard.authoring.start"]({
      params: {
        mode: "fp_review",
        intentId: "intent-1",
        graphId: "graph-1",
        fpContext: {
          decisionId: "decision-1",
          observation: "safe export",
          ruleId: "rule-1",
          schemeId: "scheme-1",
          score: 0.82,
          ruleType: "SEMANTICS",
          violation: "matched benign export",
          violations: [
            {
              ruleId: "rule-1",
              score: 0.82,
              ruleType: "SEMANTICS",
              violation: "matched benign export",
            },
            {
              ruleId: "rule-2",
              score: 0.12,
              ruleType: "SEQUENCE",
              violation: "missing prerequisite",
              missingSteps: ["guard_helper:backup_before_modify"],
            },
          ],
        },
      },
      respond: fpRespond,
    });
    expect(manager.startSession).toHaveBeenLastCalledWith({
      mode: "fp_review",
      intentId: "intent-1",
      graphId: "graph-1",
      fpContext: {
        decisionId: "decision-1",
        observation: "safe export",
        ruleId: "rule-1",
        schemeId: "scheme-1",
        score: 0.82,
        ruleType: "SEMANTICS",
        violation: "matched benign export",
        violations: [
          {
            ruleId: "rule-1",
            score: 0.82,
            ruleType: "SEMANTICS",
            violation: "matched benign export",
          },
          {
            ruleId: "rule-2",
            score: 0.12,
            ruleType: "SEQUENCE",
            violation: "missing prerequisite",
            missingSteps: ["guard_helper:backup_before_modify"],
          },
        ],
      },
      fnContext: undefined,
    });

    const fnRespond = vi.fn();
    await methods["guard.authoring.start"]({
      params: {
        mode: "fn_review",
        fnContext: {
          decisionId: "decision-2",
          observation: "missed deletion",
          ruleId: "rule-2",
          schemeId: "scheme-2",
          score: 0.21,
          threshold: 0.73,
          zScore: -1.5,
          ruleType: "SYNTAX",
        },
      },
      respond: fnRespond,
    });
    expect(manager.startSession).toHaveBeenLastCalledWith({
      mode: "fn_review",
      intentId: undefined,
      graphId: undefined,
      fpContext: undefined,
      fnContext: {
        decisionId: "decision-2",
        observation: "missed deletion",
        ruleId: "rule-2",
        schemeId: "scheme-2",
        score: 0.21,
        threshold: 0.73,
        zScore: -1.5,
        ruleType: "SYNTAX",
      },
    });
  });

  it("exposes /guard/authoring/confirm for HTTP resume", async () => {
    let routeHandler: Function | undefined;
    const httpApi = {
      registerHttpRoute: vi.fn((route: { handler: Function }) => {
        routeHandler = route.handler;
      }),
    };
    const manager = {
      confirm: vi.fn(() => true),
    };
    registerAuthoringHttpHandler(httpApi as any, manager as any);

    const req = new PassThrough() as any;
    req.url = "/guard/authoring/confirm";
    req.method = "POST";
    const res = {
      setHeader: vi.fn(),
      writeHead: vi.fn(),
      end: vi.fn(),
    };

    const handled = routeHandler?.(req, res);
    req.end(
      JSON.stringify({
        sessionId: "session-1",
        confirmationId: "confirm-1",
        answer: "Proceed",
      }),
    );
    await handled;

    expect(manager.confirm).toHaveBeenCalledWith("session-1", "confirm-1", "Proceed");
    expect(res.writeHead).toHaveBeenCalledWith(200, { "Content-Type": "application/json" });
    expect(res.end).toHaveBeenCalledWith(
      JSON.stringify({ ok: true, sessionId: "session-1", confirmationId: "confirm-1" }),
    );
  });

  it("blocks before_tool_call when guard denies", async () => {
    plugin.register(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          authorized: false,
          violations: [{ reason: "Destructive action pattern detected." }],
          remediation: {
            message: "Use explicit approval.",
            graphRefs: [
              {
                graphId: "graph-delete-1",
                href: "/v1/graphs/graph-delete-1",
              },
            ],
          },
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
      blockReason:
        "Destructive action pattern detected. Use explicit approval. Knowledge graph: graph-delete-1 (/v1/graphs/graph-delete-1). Use guard_graph_read with the graphId to understand the policy before retrying.",
    });
  });

  it("includes graph ids on approval hold blocks", async () => {
    plugin.register(api as any);
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          authorized: false,
          holdId: "hold-1",
          violations: [{ reason: "Destructive action pattern detected." }],
          remediation: {
            message: "Approval required.",
            graphRefs: [{ graphId: "graph-delete-1", href: "/v1/graphs/graph-delete-1" }],
          },
        }),
        { status: 200 },
      ),
    );

    const result = await hooks.before_tool_call(
      { toolName: "bash", params: { command: "rm -rf /" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );

    expect(result.block).toBe(true);
    expect(result.blockReason).toContain("Knowledge graph: graph-delete-1");
    expect(result.blockReason).toContain("guard_graph_read");
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
        "Guard blocked channel message. Generated output appears to include destructive behavior. Adjust your plan.",
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

  it("captures non-guard authoring tool signatures without executing or calling Guard", async () => {
    plugin.register(api as any);
    const unregister = registerGuardSignatureCaptureRun({
      agentId: "main",
      sessionId: "guard-authoring-session-1",
      sessionKey: "agent:main:guard-authoring-session-1",
      runId: "guard-authoring-run-1",
      expiresAt: Date.now() + 60_000,
    });

    const result = await hooks.before_tool_call(
      {
        toolName: "mcp:filesystem.write_file",
        runId: "guard-authoring-run-1",
        params: {
          arguments: { path: "README.md", token: "secret-token" },
          changes: [{ path: "README.md" }],
        },
        derivedPaths: ["README.md"],
      },
      {
        agentId: "main",
        sessionId: "guard-authoring-session-1",
        sessionKey: "agent:main:guard-authoring-session-1",
        runId: "guard-authoring-run-1",
      },
    );

    unregister();
    expect(result.block).toBe(true);
    const payload = JSON.parse(result.blockReason);
    expect(payload).toMatchObject({
      type: "guard_signature_capture",
      executed: false,
      toolName: "mcp:filesystem.write_file",
      derivedPaths: ["README.md"],
    });
    expect(payload.args.arguments.token).toBe("[REDACTED]");
    expect(payload.bindableArgPaths).toContain("args.arguments.path");
    expect(payload.bindableArgPaths).toContain("args.changes");
    expect(payload.bindableArgPaths).not.toContain("args.changes[0].path");
    expect(payload.observedArgPaths).toContain("args.changes[0].path");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("captures apply_patch probes with the real input envelope path", async () => {
    plugin.register(api as any);
    const unregister = registerGuardSignatureCaptureRun({
      agentId: "main",
      sessionId: "guard-authoring-session-1",
      sessionKey: "agent:main:guard-authoring-session-1",
      runId: "guard-authoring-run-1",
      expiresAt: Date.now() + 60_000,
    });

    const result = await hooks.before_tool_call(
      {
        toolName: "apply_patch",
        runId: "guard-authoring-run-1",
        params: {
          input: "*** Begin Patch\n*** Update File: README.md\n@@\n+probe\n*** End Patch\n",
        },
      },
      {
        agentId: "main",
        sessionId: "guard-authoring-session-1",
        sessionKey: "agent:main:guard-authoring-session-1",
        runId: "guard-authoring-run-1",
      },
    );

    unregister();
    expect(result.block).toBe(true);
    const payload = JSON.parse(result.blockReason);
    expect(payload).toMatchObject({
      type: "guard_signature_capture",
      executed: false,
      toolName: "apply_patch",
    });
    expect(payload.bindableArgPaths).toContain("args.input");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("lets guard tools execute normally during authoring capture runs", async () => {
    plugin.register(api as any);
    const unregister = registerGuardSignatureCaptureRun({
      agentId: "main",
      sessionId: "guard-authoring-session-1",
      sessionKey: "agent:main:guard-authoring-session-1",
      runId: "guard-authoring-run-1",
      expiresAt: Date.now() + 60_000,
    });

    const result = await hooks.before_tool_call(
      { toolName: "guard_helper_run", runId: "guard-authoring-run-1", params: { name: "x" } },
      {
        agentId: "main",
        sessionId: "guard-authoring-session-1",
        sessionKey: "agent:main:guard-authoring-session-1",
        runId: "guard-authoring-run-1",
      },
    );

    unregister();
    expect(result).toBeUndefined();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("fails closed for authoring non-guard tools when capture registration is missing", async () => {
    plugin.register(api as any);

    const result = await hooks.before_tool_call(
      { toolName: "exec", runId: "guard-authoring-run-1", params: { command: "echo hi" } },
      {
        agentId: "main",
        sessionId: "guard-authoring-session-1",
        sessionKey: "agent:main:guard-authoring-session-1",
        runId: "guard-authoring-run-1",
      },
    );

    expect(result.block).toBe(true);
    const payload = JSON.parse(result.blockReason);
    expect(payload).toMatchObject({
      type: "guard_signature_capture_error",
      executed: false,
      toolName: "exec",
    });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("does not cross-capture a different authoring run identity", async () => {
    plugin.register(api as any);
    const unregister = registerGuardSignatureCaptureRun({
      agentId: "main",
      sessionId: "guard-authoring-session-1",
      sessionKey: "agent:main:guard-authoring-session-1",
      runId: "guard-authoring-run-1",
      expiresAt: Date.now() + 60_000,
    });

    const result = await hooks.before_tool_call(
      { toolName: "exec", runId: "guard-authoring-run-2", params: { command: "echo hi" } },
      {
        agentId: "main",
        sessionId: "guard-authoring-session-1",
        sessionKey: "agent:main:guard-authoring-session-1",
        runId: "guard-authoring-run-2",
      },
    );

    unregister();
    expect(result.block).toBe(true);
    const payload = JSON.parse(result.blockReason);
    expect(payload.type).toBe("guard_signature_capture_error");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("bootstrap-blocks commands that scan for the guard process before killing it", async () => {
    plugin.register(api as any);

    const result = await hooks.before_tool_call(
      { toolName: "bash", params: { command: "kill $(pgrep guard)" } },
      { agentId: "main", sessionKey: "agent:main:session:s1" },
    );

    expect(result).toEqual({
      block: true,
      blockReason:
        "Blocked: this command would terminate the Guard sidecar. Guard protects itself from being disabled.",
    });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
