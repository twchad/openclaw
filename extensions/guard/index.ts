import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
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
  holdId?: string;
  violations?: GuardViolation[];
  remediation?: {
    message?: string;
    suggestedTools?: string[];
    retryHint?: string;
  };
  degraded?: boolean;
};

// ---------------------------------------------------------------------------
// Hold types (mirror of Guard sidecar contracts)
// ---------------------------------------------------------------------------

type HoldDecision = "allow" | "deny";

// Reads the full body of a Node IncomingMessage as a string.
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

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

  // -------------------------------------------------------------------------
  // before_tool_call: evaluate every agent tool call against Guard.
  // When Guard returns a holdId the agent fiber is suspended until the human
  // approves or the hold TTL expires.
  // -------------------------------------------------------------------------
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
      if (decision.holdId) {
        const holdId = decision.holdId;
        api.logger.info?.(`guard: hold ${holdId} created — awaiting human approval`);

        const violations = (decision.violations ?? []).map((v) => v.reason).join("; ");
        return {
          block: true,
          blockReason:
            `Guard requires human approval before this action can proceed. ` +
            `Hold ID: ${holdId}. Violations: ${violations}. ` +
            `The human can approve via the Guard dashboard, or by typing /guard-approve ${holdId}. ` +
            `Once approved, call the guard_hold_release tool with this holdId to execute the held action.`,
        };
      }

      return {
        block: true,
        blockReason: toBoundedFeedback(decision),
      };
    }
    return undefined;
  });

  // -------------------------------------------------------------------------
  // guard_hold_release — agent calls this after the human approves a hold.
  // Guard re-evaluates the frozen payload; if clean the action is released.
  // -------------------------------------------------------------------------
  api.registerTool(
    {
      name: "guard_hold_release",
      label: "Guard Hold Release",
      description:
        "Release an approved Guard hold. After the human approves a held action (via the Guard dashboard " +
        "or /guard-approve command), call this tool with the holdId to execute the original frozen action. " +
        "Guard re-evaluates the held payload against the current scheme before releasing. If the scheme " +
        "changed and new violations appeared the hold is voided and you must resubmit the original action.",
      parameters: {
        type: "object",
        properties: {
          holdId: {
            type: "string",
            description: "The hold ID returned in the block reason when Guard created the hold.",
          },
        },
        required: ["holdId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { holdId?: string };
        const holdId = typeof input.holdId === "string" ? input.holdId.trim() : "";
        if (!holdId) return { ok: false, error: "holdId is required." };

        const data = await guardFetch(
          api,
          `/v1/holds/${encodeURIComponent(holdId)}/release`,
          "POST",
        );
        if (!data) return { ok: false, error: "Guard sidecar unavailable or hold not found." };

        const result = data as { released?: boolean; reason?: string; newViolations?: unknown[] };
        if (result.released) {
          return {
            ok: true,
            released: true,
            message: "Hold released. The original action has been authorized.",
          };
        }
        return {
          ok: false,
          released: false,
          reason: result.reason ?? "UNKNOWN",
          newViolations: result.newViolations,
          message:
            result.reason === "HOLD_VOID_SCHEME_CHANGED"
              ? "The scheme changed since the hold was created. New violations were found. Resubmit the original action for a fresh approval."
              : result.reason === "HOLD_NOT_APPROVED"
                ? "The hold has not been approved yet. Wait for the human to approve via /guard-approve or the Guard dashboard."
                : `Hold could not be released: ${result.reason}`,
        };
      },
    } as AnyAgentTool,
    { optional: true },
  );

  // -------------------------------------------------------------------------
  // message_sending: evaluate every outbound agent message against Guard.
  // -------------------------------------------------------------------------
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

  // -------------------------------------------------------------------------
  // POST /guard/holds/:holdId/approve
  // Receives approval forwarded from the Guard sidecar webhook or called
  // directly by external systems. Proxies to the Guard sidecar and
  // broadcasts a notification so connected UI clients can update.
  // -------------------------------------------------------------------------
  api.registerHttpRoute({
    path: "/guard/holds/:holdId/approve",
    handler: async (req, res) => {
      if (req.method !== "POST") {
        res.statusCode = 405;
        res.end(JSON.stringify({ error: "method not allowed" }));
        return;
      }

      const url = new URL(req.url ?? "/", "http://localhost");
      const pathParts = url.pathname.split("/");
      const holdId = pathParts[3] ?? "";

      if (!holdId) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "holdId required" }));
        return;
      }

      let approvedBy = "http-callback";
      try {
        const body = await readBody(req);
        const parsed = JSON.parse(body) as { approvedBy?: string };
        if (parsed.approvedBy) approvedBy = parsed.approvedBy;
      } catch {
        // use default
      }

      // Forward to the Guard sidecar
      const cfg = resolveConfig(api);
      try {
        await fetch(`${cfg.endpoint}/v1/holds/${holdId}/approve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ approvedBy }),
          signal: AbortSignal.timeout(cfg.timeoutMs),
        });
      } catch (err) {
        api.logger.warn?.(`guard: sidecar approve failed for ${holdId}: ${String(err)}`);
      }

      api.logger.info?.(`guard: hold ${holdId} approved via HTTP callback by ${approvedBy}`);
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ ok: true, holdId }));
    },
  });

  // -------------------------------------------------------------------------
  // gateway method: guard.hold.resolve
  // Called by the Guard UI dashboard or connected clients to approve/deny.
  // -------------------------------------------------------------------------
  api.registerGatewayMethod("guard.hold.resolve", async ({ params, respond, context }) => {
    const holdId = typeof params.holdId === "string" ? params.holdId : "";
    const decision: HoldDecision = params.decision === "deny" ? "deny" : "allow";
    const resolvedBy = typeof params.resolvedBy === "string" ? params.resolvedBy : "gateway-client";

    if (!holdId) {
      respond(false, undefined, { message: "holdId required", code: "INVALID_PARAMS" });
      return;
    }

    const cfg = resolveConfig(api);
    const action = decision === "allow" ? "approve" : "deny";
    try {
      await fetch(`${cfg.endpoint}/v1/holds/${holdId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvedBy: resolvedBy }),
        signal: AbortSignal.timeout(cfg.timeoutMs),
      });
    } catch (err) {
      api.logger.warn?.(`guard: sidecar hold ${action} failed: ${String(err)}`);
    }

    context.broadcast("guard.hold.resolved", { holdId, decision, resolvedBy });
    respond(true, { ok: true, holdId, decision }, undefined);
  });

  // -------------------------------------------------------------------------
  // /guard-approve command — works across all OpenClaw text channels
  // Usage: /guard-approve <holdId> [allow|deny]
  // -------------------------------------------------------------------------
  api.registerCommand({
    name: "guard-approve",
    description: "Approve or deny a Guard hold. Usage: /guard-approve <holdId> [allow|deny]",
    acceptsArgs: true,
    requireAuth: true,
    handler: async (ctx) => {
      const rawArgs = (ctx.args ?? "").trim().split(/\s+/);
      const holdId = rawArgs[0] ?? "";
      const decisionArg = (rawArgs[1] ?? "allow").toLowerCase();
      const decision: HoldDecision = decisionArg === "deny" ? "deny" : "allow";

      if (!holdId) {
        return { text: "Usage: /guard-approve <holdId> [allow|deny]" };
      }

      // Tell the Guard sidecar.
      const cfg = resolveConfig(api);
      const action = decision === "allow" ? "approve" : "deny";
      try {
        const resp = await fetch(`${cfg.endpoint}/v1/holds/${holdId}/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ approvedBy: ctx.senderId ?? "chat-command" }),
          signal: AbortSignal.timeout(cfg.timeoutMs),
        });
        if (!resp.ok) {
          const body = (await resp.json().catch(() => ({}))) as { error?: string; status?: string };
          return {
            text: `Guard hold ${holdId}: ${body.error ?? body.status ?? "could not be updated"}.`,
          };
        }
      } catch (err) {
        return { text: `Guard sidecar unreachable: ${String(err)}` };
      }

      const verb = decision === "allow" ? "approved" : "denied";
      return {
        text: `Guard hold ${holdId} ${verb}. The agent can now call guard_hold_release to execute the held action.`,
      };
    },
  });

  // -------------------------------------------------------------------------
  // gateway_start: register this node's callback URL with the Guard sidecar
  // so Guard can POST to us when a hold is created and the agent fiber needs
  // to be suspended.
  // -------------------------------------------------------------------------
  api.on("gateway_start", async () => {
    const cfg = resolveConfig(api);
    // The callback URL uses a :holdId placeholder; Guard replaces it per hold.
    const gatewayPort = process.env.OPENCLAW_PORT ?? process.env.PORT ?? "3000";
    const callbackUrl = `http://127.0.0.1:${gatewayPort}/guard/holds/:holdId/approve`;

    try {
      const resp = await fetch(`${cfg.endpoint}/v1/config/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvalCallbackUrl: callbackUrl }),
        signal: AbortSignal.timeout(cfg.timeoutMs),
      });
      if (resp.ok) {
        api.logger.info?.(`guard: registered approval callback URL: ${callbackUrl}`);
      }
    } catch {
      // Guard may not be running yet — the GUARD_APPROVAL_CALLBACK_URL env var
      // on the Guard sidecar is the fallback for pre-configured deployments.
      api.logger.warn?.(
        `guard: could not register approval callback (Guard sidecar not reachable). Set GUARD_APPROVAL_CALLBACK_URL on the sidecar as a fallback.`,
      );
    }
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
