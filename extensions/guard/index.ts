import { randomUUID } from "node:crypto";
import type { AnyAgentTool, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";

type GuardPluginConfig = {
  endpoint?: string;
  timeoutMs?: number;
  mode?: "observe" | "enforce";
  failurePolicy?: "fail_open" | "fail_closed";
};

type GuardDecisionRequest = {
  eventType: "ACTION_EVENT" | "OUTPUT_EVENT";
  eventId: string;
  occurredAt: string;
  identity: {
    agentId: string;
    sessionKey: string;
    sessionId?: string;
    channelId?: string;
    accountId?: string;
    taskId?: string;
  };
  action?: {
    toolName: string;
    args?: Record<string, unknown>;
  };
  output?: {
    text?: string;
    payload?: unknown;
  };
};

type GuardViolation = {
  violationId?: string;
  ruleId?: string;
  reason?: string;
  ruleType?: string;
  expectedAction?: string;
  missingSteps?: string[];
  matchedPattern?: string;
};

type GuardDecisionResponse = {
  mode?: "OBSERVE" | "ENFORCE";
  authorized?: boolean;
  wouldAuthorize?: boolean;
  violations?: GuardViolation[];
  remediation?: {
    message?: string;
    suggestedTools?: string[];
    retryHint?: string;
  };
  degraded?: boolean;
};

function resolveConfig(
  api: OpenClawPluginApi,
): Required<Pick<GuardPluginConfig, "endpoint" | "timeoutMs">> &
  Pick<GuardPluginConfig, "failurePolicy"> {
  const cfg = (api.pluginConfig ?? {}) as GuardPluginConfig;
  const endpoint = (cfg.endpoint ?? process.env.GUARD_ENDPOINT ?? "http://127.0.0.1:4517").replace(
    /\/$/,
    "",
  );
  const timeoutMsRaw = cfg.timeoutMs ?? Number.parseInt(process.env.GUARD_TIMEOUT_MS ?? "", 10);
  const timeoutMs = Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? timeoutMsRaw : 5000;
  const failurePolicy =
    cfg.failurePolicy === "fail_closed" || process.env.GUARD_FAILURE_POLICY === "fail_closed"
      ? "fail_closed"
      : "fail_open";
  return { endpoint, timeoutMs, failurePolicy };
}

async function guardFetch(
  api: OpenClawPluginApi,
  path: string,
  method: string,
  body?: unknown,
): Promise<unknown | null> {
  const cfg = resolveConfig(api);
  const signal = AbortSignal.timeout(cfg.timeoutMs);
  try {
    const resp = await fetch(`${cfg.endpoint}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal,
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

async function callGuardDecision(
  api: OpenClawPluginApi,
  request: GuardDecisionRequest,
): Promise<GuardDecisionResponse> {
  const cfg = resolveConfig(api);
  const signal = AbortSignal.timeout(cfg.timeoutMs);
  try {
    const resp = await fetch(`${cfg.endpoint}/v1/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal,
    });
    if (!resp.ok) {
      throw new Error(`guard decision HTTP ${resp.status}`);
    }
    return (await resp.json()) as GuardDecisionResponse;
  } catch (err) {
    if (cfg.failurePolicy === "fail_closed") {
      return {
        mode: "ENFORCE",
        authorized: false,
        violations: [{ reason: "Guard service unavailable." }],
        remediation: { message: "Guard could not be reached and fail_closed is active." },
        degraded: true,
      };
    }
    api.logger.warn?.(`guard: decision request failed (${String(err)}), fail-open`);
    return { mode: "OBSERVE", authorized: true, degraded: true };
  }
}

function toBoundedFeedback(decision: GuardDecisionResponse): string {
  const parts: string[] = [];

  for (const v of decision.violations ?? []) {
    if (v.reason) parts.push(v.reason);
    if (v.expectedAction) parts.push(`Expected: ${v.expectedAction}`);
    if (v.missingSteps && v.missingSteps.length > 0) {
      parts.push(`Missing prerequisite steps: ${v.missingSteps.join(", ")}`);
    }
    if (v.matchedPattern) parts.push(`Triggered by pattern: ${v.matchedPattern}`);
  }

  if (decision.remediation?.message) parts.push(decision.remediation.message);
  if (decision.remediation?.retryHint) parts.push(`Hint: ${decision.remediation.retryHint}`);
  if (decision.remediation?.suggestedTools && decision.remediation.suggestedTools.length > 0) {
    parts.push(`Try calling: ${decision.remediation.suggestedTools.join(", ")}`);
  }

  return parts.length > 0
    ? parts.join(" ")
    : "Policy violation detected. Adjust your plan or request approval.";
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

function registerGuardTools(api: OpenClawPluginApi) {
  // guard_introspect -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_introspect",
      label: "Guard Introspect",
      description:
        "Get the full specification of all four Guard rule types (HARD, FUZZY, SEQUENCE, KNOWLEDGE_TEST) " +
        "including required fields, examples, composability matrix, and named composition patterns. " +
        "Call this once at the start of any policy-creation conversation to learn how to build rules. " +
        "Returns the agent's textbook for semantic authorization composition.",
      parameters: {
        type: "object",
        properties: {},
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async () => {
        const data = await guardFetch(api, "/v1/rules/spec", "GET");
        if (!data) return { ok: false, error: "Guard unavailable. Is the Guard sidecar running?" };
        return { ok: true, spec: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_validate_rule ----------------------------------------------------
  api.registerTool(
    {
      name: "guard_validate_rule",
      label: "Guard Validate Rule",
      description:
        "Validate a single Guard rule before adding it to a scheme. Submit the rule as JSON with " +
        "ruleType, title, scope, and the matching typed config (hard, fuzzy, sequence, or knowledgeTest). " +
        "Returns lint issues with severity (error/warning/info), field path, message, and fix suggestion. " +
        "Fix all errors before proceeding. Call guard_introspect first if you need the rule type specifications.",
      parameters: {
        type: "object",
        properties: {
          rule: {
            type: "object",
            description:
              "The rule spec to validate. Must include ruleType, title, scope, and the typed config object matching the ruleType.",
          },
        },
        required: ["rule"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { rule?: unknown };
        if (!input.rule) return { ok: false, error: "rule is required." };
        const data = await guardFetch(api, "/v1/rules/validate", "POST", input.rule);
        if (!data) return { ok: false, error: "Guard unavailable." };
        return { ok: true, lint: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_validate_scheme --------------------------------------------------
  api.registerTool(
    {
      name: "guard_validate_scheme",
      label: "Guard Validate Scheme",
      description:
        "Validate a complete scheme (array of rules) for both per-rule correctness and cross-rule " +
        "composition quality. Returns per-rule lint plus composition checks: coverage gaps, redundancies, " +
        "missing deterministic fallbacks, over-constraining warnings, and post-validation mutation risks. " +
        "Use this after validating individual rules to ensure they compose well together.",
      parameters: {
        type: "object",
        properties: {
          rules: {
            type: "array",
            items: { type: "object" },
            description: "Array of rule specs to validate as a composed scheme.",
          },
        },
        required: ["rules"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { rules?: unknown[] };
        if (!input.rules || input.rules.length === 0)
          return { ok: false, error: "rules array is required." };
        const data = await guardFetch(api, "/v1/schemes/validate", "POST", { rules: input.rules });
        if (!data) return { ok: false, error: "Guard unavailable." };
        return { ok: true, lint: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_compile_scheme ---------------------------------------------------
  api.registerTool(
    {
      name: "guard_compile_scheme",
      label: "Guard Compile Scheme",
      description:
        "Compile and activate a validated scheme. Runs full lint validation; if clean, saves the scheme " +
        "and binds it to the specified intent graph. Returns the scheme ID and lint results. " +
        "This is the 'ship it' step — only call after guard_validate_scheme passes cleanly.",
      parameters: {
        type: "object",
        properties: {
          intentId: { type: "string", description: "Intent ID from the saved knowledge graph." },
          graphId: { type: "string", description: "Graph ID from guard_graph_save." },
          rules: {
            type: "array",
            items: { type: "object" },
            description: "Array of validated rule specs.",
          },
          mode: {
            type: "string",
            enum: ["OBSERVE", "ENFORCE"],
            description: "OBSERVE logs but allows. ENFORCE blocks violations. Default: OBSERVE.",
          },
        },
        required: ["intentId", "graphId", "rules"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as {
          intentId?: string;
          graphId?: string;
          rules?: unknown[];
          mode?: string;
        };
        if (!input.intentId || !input.graphId || !input.rules) {
          return { ok: false, error: "intentId, graphId, and rules are required." };
        }
        const data = await guardFetch(api, "/v1/schemes/compile", "POST", {
          intentId: input.intentId,
          graphId: input.graphId,
          rules: input.rules,
          mode: input.mode ?? "OBSERVE",
        });
        if (!data) return { ok: false, error: "Guard unavailable." };
        return { ok: true, result: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_simulate ---------------------------------------------------------
  api.registerTool(
    {
      name: "guard_simulate",
      label: "Guard Simulate",
      description:
        "Test draft rules against sample events before activation. Submit rules and events to see " +
        "what would be blocked and what would pass. Use this to verify detection accuracy and check " +
        "for false positives on safe operations. Essential step before guard_compile_scheme.",
      parameters: {
        type: "object",
        properties: {
          rules: {
            type: "array",
            items: { type: "object" },
            description: "Draft rule specs to test.",
          },
          events: {
            type: "array",
            items: { type: "object" },
            description:
              "Sample GuardDecisionRequest events. Include both events that should be blocked and events that should be allowed.",
          },
        },
        required: ["rules", "events"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { rules?: unknown[]; events?: unknown[] };
        if (!input.rules || !input.events)
          return { ok: false, error: "rules and events are required." };
        const data = await guardFetch(api, "/v1/schemes/simulate", "POST", {
          rules: input.rules,
          events: input.events,
        });
        if (!data) return { ok: false, error: "Guard unavailable." };
        return { ok: true, simulation: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_graph_save -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_graph_save",
      label: "Guard Graph Save",
      description:
        "Save an agent-constructed knowledge graph. Build the graph to map user intent to risk surfaces: " +
        "nodes represent concepts (intent, tool calls, output content, approval gates) and edges represent " +
        "relationships (constrains, enables, exception). Returns the saved graph with generated IDs. " +
        "Call this before guard_compile_scheme to establish the intent context.",
      parameters: {
        type: "object",
        properties: {
          intentText: {
            type: "string",
            description: "The user's policy intent in natural language.",
          },
          nodes: {
            type: "array",
            items: { type: "object" },
            description:
              "Graph nodes. Each needs at minimum: label, kind (intent|action-surface|output-surface|approval|risk), safeHint.",
          },
          edges: {
            type: "array",
            items: { type: "object" },
            description:
              "Graph edges. Each needs: source (nodeId), target (nodeId), relType (constrains|enables|exception|requires).",
          },
          modeState: {
            type: "string",
            enum: ["OBSERVE", "ENFORCE"],
            description: "Initial mode. Default: OBSERVE.",
          },
        },
        required: ["intentText", "nodes", "edges"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as {
          intentText?: string;
          nodes?: unknown[];
          edges?: unknown[];
          modeState?: string;
        };
        if (!input.intentText || !input.nodes) {
          return { ok: false, error: "intentText and nodes are required." };
        }
        const data = await guardFetch(api, "/v1/graphs/", "POST", {
          intentText: input.intentText,
          nodes: input.nodes,
          edges: input.edges ?? [],
          modeState: input.modeState ?? "OBSERVE",
        });
        if (!data) return { ok: false, error: "Guard unavailable." };
        return { ok: true, graph: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // guard_graph_read -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_graph_read",
      label: "Guard Graph Read",
      description:
        "Read a Guard intent knowledge graph by ID. Returns safe graph context only; " +
        "it never returns the full auth scheme.",
      parameters: {
        type: "object",
        properties: {
          graphId: { type: "string", description: "Guard graph ULID." },
        },
        required: ["graphId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = (params as { graphId?: string }) ?? {};
        const graphId = typeof input.graphId === "string" ? input.graphId.trim() : "";
        if (!graphId) return { ok: false, error: "graphId is required." };
        const data = await guardFetch(api, `/v1/graphs/${encodeURIComponent(graphId)}`, "GET");
        if (!data) return { ok: false, error: "Graph not found or Guard unavailable." };
        return { ok: true, graph: data };
      },
    } as AnyAgentTool,
    { optional: true },
  );
}

// ---------------------------------------------------------------------------
// Hook registration
// ---------------------------------------------------------------------------

export function registerGuardPlugin(api: OpenClawPluginApi) {
  registerGuardTools(api);

  api.on("before_tool_call", async (event, ctx) => {
    const decision = await callGuardDecision(api, {
      eventType: "ACTION_EVENT",
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      identity: {
        agentId: ctx.agentId ?? "main",
        sessionKey: ctx.sessionKey ?? "",
        sessionId: ctx.sessionKey ?? "",
      },
      action: {
        toolName: event.toolName,
        args: event.params ?? {},
      },
    });

    if (decision.authorized === false) {
      return {
        block: true,
        blockReason: toBoundedFeedback(decision),
      };
    }
    return undefined;
  });

  api.on("message_sending", async (event, ctx) => {
    const decision = await callGuardDecision(api, {
      eventType: "OUTPUT_EVENT",
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      identity: {
        agentId: "main",
        sessionKey: ctx.conversationId ?? "",
        sessionId: ctx.conversationId,
        channelId: ctx.channelId,
        accountId: ctx.accountId,
      },
      output: {
        text: event.content ?? "",
      },
    });

    if (decision.authorized === false) {
      const feedback = toBoundedFeedback(decision);
      return {
        content: `Guard blocked message output. ${feedback}`,
      };
    }
    return undefined;
  });
}

const plugin = {
  id: "guard",
  name: "Guard",
  description: "Semantic authorization adapter for OpenClaw using Guard sidecar.",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    registerGuardPlugin(api);
  },
};

export default plugin;
