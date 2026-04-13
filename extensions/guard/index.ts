import { randomUUID } from "node:crypto";
import type { AnyAgentTool, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN } from "./src/authoring-allowlist-token.js";
import {
  AuthoringSessionManager,
  registerAuthoringGateway,
  registerAuthoringHttpHandler,
} from "./src/authoring.js";

function jsonResult(payload: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    details: payload,
  };
}

type GuardPluginConfig = {
  endpoint?: string;
  timeoutMs?: number;
  mode?: "observe" | "enforce";
  failurePolicy?: "fail_open" | "fail_closed";
};

type GuardDecisionRequest = {
  eventType: "ACTION_EVENT" | "CHANNEL_EVENT";
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
  channel?: {
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
  pendingKnowledgeTest?: boolean;
  knowledgeTestQuestion?: string;
  violations?: GuardViolation[];
  remediation?: {
    message?: string;
    suggestedTools?: string[];
    retryHint?: string;
  };
  degraded?: boolean;
};

type HoldReleaseResponse = {
  holdId: string;
  status: string;
  frozenRequest?: unknown;
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
  extraHeaders?: Record<string, string>,
): Promise<unknown | null> {
  const cfg = resolveConfig(api);
  const signal = AbortSignal.timeout(cfg.timeoutMs);
  try {
    const resp = await fetch(`${cfg.endpoint}${path}`, {
      method,
      headers: {
        ...(body ? { "Content-Type": "application/json" } : {}),
        ...extraHeaders,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal,
    });
    if (!resp.ok) {
      // 4xx = client error (validation failure, not found, etc.) — return the
      // response body so callers surface the real error instead of "Guard unavailable."
      if (resp.status >= 400 && resp.status < 500) {
        try {
          return await resp.json();
        } catch {
          return { error: `Guard returned HTTP ${resp.status}` };
        }
      }
      return null;
    }
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
// Browser semantic enrichment cache
//
// Enriches bare browser actions (e.g. "click ref=e42") with element names,
// URLs, page context, and nearby snapshot lines before sending to Guard.
//
// Populated by after_tool_call from snapshot results; consumed by
// before_tool_call to enrich outgoing Guard decision requests.
//
// NOTE: OpenClaw provides ctx.sessionKey in before_tool_call but NOT in
// after_tool_call. We use a single shared state instance so both hooks
// operate on the same data. For multi-agent / multi-tab support, key on
// targetId instead (each browser tab has a unique one).
// ---------------------------------------------------------------------------

type BrowserRefMeta = { role: string; name?: string };

type BrowserActionEntry = {
  kind: string;
  ref?: string;
  refRole?: string;
  refName?: string;
  ts: number;
};

type BrowserSemanticState = {
  url?: string;
  targetId?: string;
  profile?: string;
  lastSnapshotText?: string;
  refs: Record<string, BrowserRefMeta>;
  recentActions: BrowserActionEntry[];
  lastAccessedAt: number;
};

const BROWSER_STATE_MAX_ACTIONS = 5;
const BROWSER_STATE_MAX_SNAPSHOT_CHARS = 60000;

let browserState: BrowserSemanticState = {
  refs: {},
  recentActions: [],
  lastAccessedAt: Date.now(),
};

function getBrowserState(): BrowserSemanticState {
  browserState.lastAccessedAt = Date.now();
  return browserState;
}

function findNearbySnapshotLines(snapshot: string, ref: string, radius: number): string {
  const lines = snapshot.split("\n");
  const refPattern = `[ref=${ref}]`;
  const idx = lines.findIndex((line) => line.includes(refPattern));
  if (idx < 0) return "";
  const start = Math.max(0, idx - radius);
  const end = Math.min(lines.length, idx + radius + 1);
  return lines.slice(start, end).join("\n");
}

/**
 * When the target ref itself has no name (e.g. a nameless "generic" div),
 * walk the snapshot tree downward from that ref to find the first named
 * child element. Returns { role, name } of the first named descendant,
 * or null if none found within a reasonable depth.
 */
function resolveChildName(snapshot: string, ref: string): { role: string; name: string } | null {
  const lines = snapshot.split("\n");
  const refPattern = `[ref=${ref}]`;
  const idx = lines.findIndex((line) => line.includes(refPattern));
  if (idx < 0) return null;

  // Measure the indent of the target line to know when we've left its subtree
  const targetIndent = lines[idx].search(/\S/);

  // Scan children (lines below with deeper indent)
  const namePattern = /(\w+)\s+(?:\\?"*)([^"\\]+?)(?:\\?"*)\s+\[ref=e\d+\]/;
  for (let i = idx + 1; i < Math.min(lines.length, idx + 20); i++) {
    const lineIndent = lines[i].search(/\S/);
    if (lineIndent < 0) continue;
    if (lineIndent <= targetIndent) break; // left the subtree

    const m = namePattern.exec(lines[i]);
    if (m && m[2]) {
      return { role: m[1], name: m[2] };
    }
  }
  return null;
}

/**
 * Extracts ref metadata from snapshot text via regex.
 * Handles multiple formats from OpenClaw's accessibility tree:
 *   button "Buy Now" [ref=e9]       (raw text, quotes)
 *   button \"Buy Now\" [ref=e9]     (JSON-escaped quotes)
 *   button[Buy Now] [ref=e9]        (bracket format)
 */
function parseRefsFromSnapshotText(text: string): Record<string, BrowserRefMeta> {
  const refs: Record<string, BrowserRefMeta> = {};

  // Pattern 1: role "name" [ref=eN] or role \"name\" [ref=eN]
  const quotedPattern = /(\w+)\s+(?:\\?"+)([^"\\]+)(?:\\?"+)\s+\[ref=(e\d+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = quotedPattern.exec(text)) !== null) {
    refs[m[3]] = { role: m[1], name: m[2] };
  }

  // Pattern 2: role[name] [ref=eN]
  const bracketPattern = /(\w+)\[([^\]]+)\]\s+\[ref=(e\d+)\]/g;
  while ((m = bracketPattern.exec(text)) !== null) {
    if (!refs[m[3]]) {
      refs[m[3]] = { role: m[1], name: m[2] };
    }
  }

  // Pattern 3: bare role [ref=eN] (no name)
  const barePattern = /(\w+)\s+\[ref=(e\d+)\]/g;
  while ((m = barePattern.exec(text)) !== null) {
    if (!refs[m[2]]) {
      refs[m[2]] = { role: m[1] };
    }
  }

  return refs;
}

/**
 * Decomposes the combined "browser" tool (action=act|navigate|open) into a
 * synthetic tool name (e.g. browser_click) with enriched arguments drawn
 * from the cached snapshot state.
 */
function enrichBrowserAction(
  params: Record<string, unknown>,
): { toolName: string; args: Record<string, unknown> } | null {
  const action = typeof params.action === "string" ? params.action : "";
  if (action !== "act" && action !== "navigate" && action !== "open") return null;

  const state = getBrowserState();
  const profile = typeof params.profile === "string" ? params.profile : undefined;
  const targetId = typeof params.targetId === "string" ? params.targetId : undefined;

  if (action === "navigate" || action === "open") {
    const targetUrl = typeof params.targetUrl === "string" ? params.targetUrl : "";
    return {
      toolName: "browser_navigate",
      args: {
        url: targetUrl,
        ...(state.url ? { priorUrl: state.url } : {}),
        ...(profile ? { profile } : {}),
        ...(targetId ? { targetId } : {}),
      },
    };
  }

  const request = params.request as Record<string, unknown> | undefined;
  if (!request || typeof request !== "object") return null;

  const kind = typeof request.kind === "string" ? request.kind : "";
  if (!kind) return null;

  const ref = typeof request.ref === "string" ? request.ref : undefined;
  const refMeta = ref ? state.refs[ref] : undefined;
  const text = typeof request.text === "string" ? request.text : undefined;
  const fn = typeof request.fn === "string" ? request.fn : undefined;

  const syntheticTool = `browser_${kind}`;
  const enrichedArgs: Record<string, unknown> = {};

  if (state.url) enrichedArgs.url = state.url;
  if (ref) enrichedArgs.ref = ref;
  if (refMeta?.role) enrichedArgs.refRole = refMeta.role;
  if (refMeta?.name) enrichedArgs.refName = refMeta.name;
  if (text) enrichedArgs.text = text;
  if (fn) enrichedArgs.expression = fn;
  if (profile) enrichedArgs.profile = profile;
  if (targetId) enrichedArgs.targetId = targetId;

  // Resolve a meaningful element name:
  //  1. Direct ref name (e.g. button "Buy Now")
  //  2. First named child in the snapshot tree (e.g. generic div containing img "Logo")
  //  3. Raw nearby snapshot lines as last resort
  if (refMeta?.name) {
    enrichedArgs.element = refMeta.name;
  } else if (ref && state.lastSnapshotText) {
    const child = resolveChildName(state.lastSnapshotText, ref);
    if (child) {
      enrichedArgs.element = child.name;
      enrichedArgs.refName = child.name;
      enrichedArgs.refRole = `${refMeta?.role ?? "unknown"} > ${child.role}`;
    } else {
      const nearby = findNearbySnapshotLines(state.lastSnapshotText, ref, 3);
      if (nearby) enrichedArgs.nearbyContext = nearby;
    }
  }

  // For ref-less actions (evaluate, etc.) include top page elements as context
  if (!ref && Object.keys(state.refs).length > 0) {
    const pageElements = Object.entries(state.refs)
      .filter(([, meta]) => meta.name)
      .map(([, meta]) => `${meta.role}:"${meta.name}"`)
      .slice(0, 30)
      .join(", ");
    if (pageElements) enrichedArgs.pageContext = pageElements;
  }

  if (typeof request.values !== "undefined") enrichedArgs.values = request.values;
  if (typeof request.fields !== "undefined") enrichedArgs.fields = request.fields;

  if (state.recentActions.length > 0) {
    const prior = state.recentActions[state.recentActions.length - 1];
    enrichedArgs.priorAction = `${prior.kind}${prior.refName ? " " + prior.refName : ""}`;
  }

  return { toolName: syntheticTool, args: enrichedArgs };
}

/**
 * Enriches args for direct browser_* MCP tools (browser_click, browser_evaluate,
 * etc.) using the cached snapshot state. Same enrichment logic as the combined
 * "browser" tool path, just for the split-tool API.
 */
function enrichDirectBrowserTool(rawArgs: Record<string, unknown>): Record<string, unknown> {
  const state = getBrowserState();
  const args = { ...rawArgs };

  if (state.url && !args.url) args.url = state.url;
  if (state.targetId && !args.targetId && !args.viewId) args.targetId = state.targetId;

  // Normalize JS code: fn → expression for consistent Guard evaluation
  if (typeof args.fn === "string" && args.fn && !args.expression) {
    args.expression = args.fn;
  }

  const ref = typeof args.ref === "string" ? args.ref : undefined;
  const meta = ref ? state.refs[ref] : undefined;
  if (meta) {
    if (meta.role && !args.refRole) args.refRole = meta.role;
    if (meta.name) {
      if (!args.element) args.element = meta.name;
      if (!args.refName) args.refName = meta.name;
    }
  }
  // When the ref itself has no name, try the first named child element
  if (ref && !args.element && state.lastSnapshotText) {
    const child = resolveChildName(state.lastSnapshotText, ref);
    if (child) {
      args.element = child.name;
      args.refName = child.name;
      args.refRole = `${meta?.role ?? "unknown"} > ${child.role}`;
    } else {
      const nearby = findNearbySnapshotLines(state.lastSnapshotText, ref, 3);
      if (nearby) args.nearbyContext = nearby;
    }
  }

  // For ref-less actions, include key page elements so semantic rules can
  // catch dangerous actions (e.g. clicking "Buy Now" on Amazon)
  if (!ref && Object.keys(state.refs).length > 0) {
    const pageElements = Object.entries(state.refs)
      .filter(([, meta]) => meta.name)
      .map(([, meta]) => `${meta.role}:"${meta.name}"`)
      .slice(0, 30)
      .join(", ");
    if (pageElements) args.pageContext = pageElements;
  }

  if (state.recentActions.length > 0 && !args.priorAction) {
    const prior = state.recentActions[state.recentActions.length - 1];
    args.priorAction = `${prior.kind}${prior.refName ? " " + prior.refName : ""}`;
  }

  return args;
}

// ---------------------------------------------------------------------------
// Snapshot extraction from AgentToolResult
//
// AgentToolResult = { content: [{type:"text", text:"..."}], details: T }
// The raw accessibility tree lives in details.snapshot (preferred) or
// content[0].text (fallback). details.refs is an integer count, not a map,
// so we always regex-parse refs from the text.
// ---------------------------------------------------------------------------

type AgentToolResultLike = {
  content?: Array<{ type?: string; text?: string }>;
  details?: Record<string, unknown>;
};

/** Extracts the raw accessibility-tree text from an AgentToolResult. */
function extractSnapshotText(result: unknown): string {
  if (typeof result === "string") return result;
  if (!result || typeof result !== "object") return "";
  const r = result as AgentToolResultLike;

  if (r.details && typeof r.details.snapshot === "string" && r.details.snapshot) {
    return r.details.snapshot;
  }
  if (Array.isArray(r.content)) {
    for (const item of r.content) {
      if (item && typeof item.text === "string" && item.text) return item.text;
    }
  }
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

/**
 * Ingests snapshot data from a tool result into the browser state cache.
 * Only updates refs/text when the new snapshot is at least as rich as the
 * existing one — the after_tool_call hook fires twice per tool call, and
 * the second invocation often carries a truncated result.
 */
function ingestSnapshot(state: BrowserSemanticState, result: unknown): void {
  const text = extractSnapshotText(result);
  if (!text) return;

  const newRefs = parseRefsFromSnapshotText(text);
  const newRefCount = Object.keys(newRefs).length;
  const oldRefCount = Object.keys(state.refs).length;

  if (newRefCount >= oldRefCount) {
    state.refs = newRefs;
    state.lastSnapshotText = text.slice(0, BROWSER_STATE_MAX_SNAPSHOT_CHARS);
  }

  // Pull URL and targetId from result.details if available
  if (result && typeof result === "object" && !Array.isArray(result)) {
    const details = (result as AgentToolResultLike).details ?? (result as Record<string, unknown>);
    if (typeof details.url === "string" && details.url) state.url = details.url;
    if (typeof details.targetId === "string" && details.targetId) state.targetId = details.targetId;
  }
}

function isSnapshotTool(toolName: string, params: Record<string, unknown>): boolean {
  return (
    toolName === "browser_snapshot" || (toolName === "browser" && params.action === "snapshot")
  );
}

function isNavigateTool(toolName: string, params: Record<string, unknown>): boolean {
  return (
    toolName === "browser_navigate" ||
    (toolName === "browser" && (params.action === "navigate" || params.action === "open"))
  );
}

/** True if the result contains snapshot data regardless of which tool produced it. */
function resultHasSnapshot(result: unknown): boolean {
  const text = extractSnapshotText(result);
  return text.length > 50 && text.includes("[ref=");
}

/**
 * Updates the shared browser state from a tool result.
 * - Captures profile, targetId, URL from params
 * - Ingests snapshot data when present (many browser actions return one implicitly)
 * - Tracks recent non-snapshot actions for priorAction enrichment
 */
function updateBrowserStateFromResult(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): void {
  if (!toolName.startsWith("browser")) return;
  const state = getBrowserState();

  if (typeof params.profile === "string") state.profile = params.profile;
  if (typeof params.targetId === "string" && params.targetId) state.targetId = params.targetId;
  if (typeof params.viewId === "string" && params.viewId) state.targetId = params.viewId;

  if (isNavigateTool(toolName, params)) {
    const url = (params.url ?? params.targetUrl) as string | undefined;
    if (url) state.url = url;
  }

  if (resultHasSnapshot(result)) {
    ingestSnapshot(state, result);
    return;
  }

  if (isSnapshotTool(toolName, params) || isNavigateTool(toolName, params)) return;

  // Track non-snapshot actions (click, fill, etc.) for priorAction context
  const ref = typeof params.ref === "string" ? params.ref : undefined;
  const refMeta = ref ? state.refs[ref] : undefined;
  const kind =
    toolName === "browser"
      ? typeof (params.request as Record<string, unknown>)?.kind === "string"
        ? ((params.request as Record<string, unknown>).kind as string)
        : "unknown"
      : toolName.replace("browser_", "");

  state.recentActions.push({
    kind,
    ref,
    refRole: refMeta?.role,
    refName: refMeta?.name,
    ts: Date.now(),
  });
  if (state.recentActions.length > BROWSER_STATE_MAX_ACTIONS) state.recentActions.shift();
}

// ---------------------------------------------------------------------------
// Bootstrap self-protection: evaluated in-process before the sidecar call.
// Catches process-kill patterns that would take down guardd, and browser
// navigation to Guard ports. If the sidecar is dead these still fire.
// ---------------------------------------------------------------------------

const SHELL_TOOLS = new Set([
  "bash",
  "shell",
  "terminal",
  "exec",
  "run_command",
  "execute",
  "computer",
  "sh",
  "zsh",
  "subprocess",
  "command",
]);

const SYSTEM_DENY_PATTERNS = [
  "kill guardd",
  "pkill guardd",
  "killall guardd",
  "kill -9 guardd",
  "kill -KILL guardd",
  "kill -TERM guardd",
  "kill -15 guardd",
  "kill -SIGTERM guardd",
  "kill -SIGKILL guardd",
  "pkill -9 guardd",
  "pkill -f guardd",
  "kill guard",
  "pkill guard",
  "killall guard",
  "kill -9 guard",
  "pkill -9 guard",
  "pkill -f guard",
  "launchctl stop guard",
  "launchctl unload guard",
  "launchctl remove guard",
  "launchctl kill guard",
  "systemctl stop guard",
  "systemctl disable guard",
  "systemctl kill guard",
  "kill $(lsof -t -i:4517)",
  "kill $(lsof -t -i:4520)",
  "fuser -k 4517/tcp",
  "fuser -k 4520/tcp",
  "lsof -ti:4517",
  "lsof -ti:4520",
];

const SYSTEM_DENY_URLS = [
  "127.0.0.1:4517",
  "127.0.0.1:4520",
  "localhost:4517",
  "localhost:4520",
  "0.0.0.0:4517",
  "0.0.0.0:4520",
];

function flattenArgs(args: Record<string, unknown>): string {
  return Object.values(args)
    .filter((v) => typeof v === "string")
    .join(" ");
}

function bootstrapBlock(
  toolName: string,
  params: Record<string, unknown> | undefined,
): string | null {
  if (SHELL_TOOLS.has(toolName)) {
    const cmdText = flattenArgs(params ?? {}).toLowerCase();
    for (const pattern of SYSTEM_DENY_PATTERNS) {
      if (cmdText.includes(pattern)) {
        return "Blocked: this command would terminate the Guard sidecar. Guard protects itself from being disabled.";
      }
    }
  }

  if (toolName === "browser_navigate" || toolName === "browser") {
    const url = String(
      (params as Record<string, unknown>)?.url ??
        (params as Record<string, unknown>)?.targetUrl ??
        "",
    ).toLowerCase();
    for (const deny of SYSTEM_DENY_URLS) {
      if (url.includes(deny)) {
        return "Blocked: navigating to the Guard service port is not allowed.";
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

function registerAuthoringTools(api: OpenClawPluginApi) {
  const guardAuthoringToolOpts = {
    optional: true as const,
    optionalRequiresAllowlistToken: GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN,
  };
  // guard_introspect -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_introspect",
      label: "Guard Introspect",
      description:
        "Get the full specification of current Guard rule types (SYNTAX, SEMANTICS, SEQUENCE, SEMANTICS_SEQUENCE, SENSITIVE_DATA, KNOWLEDGE_TEST) " +
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
        if (!data)
          return jsonResult({
            ok: false,
            error: "Guard unavailable. Is the Guard sidecar running?",
          });
        return jsonResult({ ok: true, spec: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
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
        if (!input.rule) return jsonResult({ ok: false, error: "rule is required." });
        const data = await guardFetch(api, "/v1/rules/validate", "POST", input.rule);
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, lint: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
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
          return jsonResult({ ok: false, error: "rules array is required." });
        const data = await guardFetch(api, "/v1/schemes/validate", "POST", { rules: input.rules });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, lint: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
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
          approvalRequired: {
            type: "boolean",
            description:
              "If true, violations create approval holds instead of outright blocking. " +
              "A human must approve or reject each held action within the approval window.",
          },
          approvalWindowSeconds: {
            type: "number",
            description:
              "Seconds to wait for human approval before auto-expiring a hold. Default: 300 (5 minutes). " +
              "Only relevant when approvalRequired is true.",
          },
          exceptions: {
            type: "array",
            items: {
              type: "object",
              properties: {
                exceptionId: { type: "string", description: "Unique exception identifier." },
                description: {
                  type: "string",
                  description: "Human-readable description of when this exception applies.",
                },
                script: {
                  type: "string",
                  description:
                    "Starlark script that returns True to exempt the action from the scheme. " +
                    "Receives the same context as codegates (tool name, args, identity).",
                },
              },
              required: ["exceptionId", "script"],
            },
            description:
              "Scheme-level exceptions (Starlark codegates that exempt actions from ALL rules). " +
              "Use for blanket overrides like admin bypass or test-mode exemptions.",
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
          approvalRequired?: boolean;
          approvalWindowSeconds?: number;
          exceptions?: unknown[];
        };
        if (!input.intentId || !input.graphId || !input.rules) {
          return jsonResult({ ok: false, error: "intentId, graphId, and rules are required." });
        }
        const payload: Record<string, unknown> = {
          intentId: input.intentId,
          graphId: input.graphId,
          rules: input.rules,
          mode: input.mode ?? "OBSERVE",
        };
        if (input.approvalRequired != null) payload.approvalRequired = input.approvalRequired;
        if (input.approvalWindowSeconds != null)
          payload.approvalWindowSeconds = input.approvalWindowSeconds;
        if (input.exceptions) payload.exceptions = input.exceptions;
        const data = await guardFetch(api, "/v1/schemes/compile", "POST", payload);
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, result: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_scheme_update -----------------------------------------------------
  api.registerTool(
    {
      name: "guard_scheme_update",
      label: "Guard Scheme Update",
      description:
        "Update an existing scheme with partial changes instead of recompiling the entire scheme. " +
        "Send only the delta: scheme-level patches (mode, approvalRequired, approvalWindowSeconds, " +
        "knowledgeTest, exceptions) and/or rule mutations (updateRules by ruleId, addRules, " +
        "removeRuleIds). The server reads the current scheme, applies patches, runs full validation " +
        "+ lint + smoke test, and creates a new versioned scheme. Use this for all modifications " +
        "after initial compilation. Use guard_compile_scheme only for the first scheme creation.",
      parameters: {
        type: "object",
        properties: {
          schemeId: {
            type: "string",
            description: "Target scheme ID. Optional if intentId is provided.",
          },
          intentId: {
            type: "string",
            description: "Target intent ID — resolves to the active scheme for this intent.",
          },
          mode: {
            type: "string",
            enum: ["OBSERVE", "ENFORCE"],
            description: "Set scheme mode. Omit to keep current.",
          },
          approvalRequired: {
            type: "boolean",
            description: "Set whether violations require human approval. Omit to keep current.",
          },
          approvalWindowSeconds: {
            type: "number",
            description: "Set approval timeout in seconds. Omit to keep current.",
          },
          knowledgeTest: {
            type: "object",
            properties: {
              question: { type: "string", description: "Question the agent must answer." },
              expectedAnswer: { type: "string", description: "Expected answer." },
              threshold: { type: "number", description: "Similarity threshold (0-1)." },
              maxRetries: { type: "number", description: "Max retry attempts." },
            },
            description:
              "Set or replace the scheme-level knowledge test gate. Omit to keep current.",
          },
          exceptions: {
            type: "array",
            items: {
              type: "object",
              properties: {
                exceptionId: { type: "string" },
                description: { type: "string" },
                script: { type: "string" },
              },
              required: ["exceptionId", "script"],
            },
            description: "Replace scheme exceptions. Omit to keep current.",
          },
          updateRules: {
            type: "array",
            items: {
              type: "object",
              properties: {
                ruleId: { type: "string", description: "ID of the rule to patch (required)." },
                title: { type: "string", description: "New title. Omit to keep current." },
                description: {
                  type: "string",
                  description: "New description. Omit to keep current.",
                },
                scope: { type: "string", description: "New scope. Omit to keep current." },
                enabled: {
                  type: "boolean",
                  description: "Enable/disable rule. Omit to keep current.",
                },
                syntax: {
                  type: "object",
                  properties: {
                    denyPattern: { type: "array", items: { type: "string" } },
                    toolFilter: { type: "array", items: { type: "string" } },
                  },
                  description: "Patch SYNTAX config fields. Omit fields to keep current.",
                },
                semantics: {
                  type: "object",
                  properties: {
                    elaborations: { type: "array", items: { type: "string" } },
                    threshold: { type: "number" },
                    toolFilter: { type: "array", items: { type: "string" } },
                    contentTypes: { type: "array", items: { type: "string" } },
                    benignCorpus: { type: "array", items: { type: "string" } },
                  },
                  description: "Patch SEMANTICS config fields. Omit fields to keep current.",
                },
                sequence: { type: "object", description: "Replace entire SEQUENCE config." },
                semanticsSequence: {
                  type: "object",
                  description: "Replace entire SEMANTICS_SEQUENCE config.",
                },
                sensitiveData: {
                  type: "object",
                  description: "Replace entire SENSITIVE_DATA config.",
                },
                codeGate: { type: "object", description: "Replace entire codeGate config." },
                knowledgeTest: {
                  type: "object",
                  description: "Replace entire knowledgeTest config.",
                },
              },
              required: ["ruleId"],
            },
            description: "Patch existing rules by ruleId. Only provided fields are changed.",
          },
          addRules: {
            type: "array",
            items: { type: "object" },
            description: "New RuleSpec entries to append to the scheme.",
          },
          removeRuleIds: {
            type: "array",
            items: { type: "string" },
            description: "Rule IDs to remove from the scheme.",
          },
        },
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as Record<string, unknown>;
        if (!input.intentId && !input.schemeId) {
          return jsonResult({ ok: false, error: "schemeId or intentId is required." });
        }
        const data = await guardFetch(api, "/v1/schemes/update", "POST", input);
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, result: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
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
          return jsonResult({ ok: false, error: "rules and events are required." });
        const data = await guardFetch(api, "/v1/schemes/simulate", "POST", {
          rules: input.rules,
          events: input.events,
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, simulation: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
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
          graphId: {
            type: "string",
            description:
              "Optional existing graph ID to update/reuse. Leave empty to create a new graph.",
          },
          intentId: {
            type: "string",
            description:
              "Optional existing intent ID to reuse. Leave empty to auto-generate a new intent ID.",
          },
          intentText: {
            type: "string",
            description: "The user's policy intent in natural language.",
          },
          nodes: {
            type: "array",
            items: {
              type: "object",
              properties: {
                nodeId: {
                  type: "string",
                  description: "Unique node identifier used by edges (required).",
                },
                label: {
                  type: "string",
                  description: "Human-readable node label (required).",
                },
                kind: {
                  type: "string",
                  enum: ["intent", "action-surface", "channel-surface", "exception", "gate"],
                  description:
                    "Node kind. Use intent/action-surface/channel-surface/exception/gate.",
                },
                safeHint: {
                  type: "string",
                  description: "Operator-facing summary of what this node protects/represents.",
                },
                observableId: {
                  type: "string",
                  description: "Optional external observable reference.",
                },
              },
              required: ["nodeId", "label", "kind"],
              additionalProperties: false,
            },
            description: "Graph nodes. Each node must include nodeId, label, and kind.",
          },
          edges: {
            type: "array",
            items: {
              type: "object",
              properties: {
                edgeId: {
                  type: "string",
                  description: "Optional edge identifier.",
                },
                source: {
                  type: "string",
                  description: "Source nodeId (required).",
                },
                target: {
                  type: "string",
                  description: "Target nodeId (required).",
                },
                relType: {
                  type: "string",
                  description:
                    "Relationship type (recommended): constrains, governs, exception_for, prerequisite_for.",
                },
              },
              required: ["source", "target"],
              additionalProperties: false,
            },
            description: "Graph edges connecting nodeId references.",
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
          graphId?: string;
          intentId?: string;
          intentText?: string;
          nodes?: unknown[];
          edges?: unknown[];
          modeState?: string;
        };
        if (!input.intentText || !input.nodes) {
          return jsonResult({ ok: false, error: "intentText and nodes are required." });
        }
        const data = await guardFetch(api, "/v1/graphs/", "POST", {
          graphId: input.graphId,
          intentId: input.intentId,
          intentText: input.intentText,
          nodes: input.nodes,
          edges: input.edges ?? [],
          modeState: input.modeState ?? "OBSERVE",
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, graph: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_create -----------------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_create",
      label: "Guard Helper Create",
      description:
        "Create or update a Guard-managed helper. Each helper is a directory-based project " +
        "on disk that persists state between runs. The entrypoint script receives JSON on " +
        "stdin and must write JSON to stdout. For simple helpers, provide the script directly. " +
        "For complex helpers beyond your capability, set stub:true to scaffold a directory " +
        "with a README for the user to implement. Reference in SEQUENCE rules as " +
        "guard_helper:<name> in requiredTools.",
      parameters: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Unique helper name (used as guard_helper:<name> in SEQUENCE rules).",
          },
          description: { type: "string", description: "What this helper does." },
          runtime: {
            type: "string",
            enum: ["node", "python", "shell"],
            description: "Script runtime.",
          },
          script: {
            type: "string",
            description:
              "The entrypoint script source. Reads JSON from stdin, writes JSON to stdout. " +
              "Optional if stub:true.",
          },
          stub: {
            type: "boolean",
            description:
              "If true, scaffolds a stub directory with README for user implementation. " +
              "Use when the helper is too complex to write inline (needs deps, DB, external APIs).",
          },
          entrypoint: {
            type: "string",
            description: "Custom entrypoint filename. Defaults to main.{ext}.",
          },
          files: {
            type: "object",
            additionalProperties: { type: "string" },
            description:
              "Additional files to write: {filename: content}. E.g. " +
              '{"requirements.txt": "requests\\nnumpy\\n", "utils.py": "..."}.',
          },
          inputSchema: {
            type: "object",
            additionalProperties: { type: "string" },
            description: "Optional map of input field names to descriptions.",
          },
          permissions: {
            type: "object",
            properties: {
              network: {
                type: "array",
                items: { type: "string" },
                description: "Allowed domains for network access.",
              },
              full: { type: "boolean", description: "Unrestricted subprocess access." },
            },
            description:
              "Permission level. Omit for restricted (auto-approved). Network/full require dashboard approval.",
          },
          helperId: {
            type: "string",
            description: "If provided, updates an existing helper instead of creating a new one.",
          },
          schemeId: { type: "string", description: "Optional scheme ID to associate with." },
          intentId: { type: "string", description: "Optional intent ID to associate with." },
        },
        required: ["name", "runtime"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as Record<string, unknown>;
        const data = await guardFetch(api, "/v1/authoring/helper", "POST", input, {
          "X-Guard-Role": "author",
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_test -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_test",
      label: "Guard Helper Test",
      description:
        "Test a Guard-managed helper with sample inputs. Runs the helper in a sandbox " +
        "without recording an attestation. Use to verify helper behavior before compiling " +
        "the scheme.",
      parameters: {
        type: "object",
        properties: {
          helperId: {
            type: "string",
            description: "The helper ID returned by guard_helper_create.",
          },
          inputs: { type: "object", description: "JSON inputs to pass to the helper via stdin." },
        },
        required: ["helperId", "inputs"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { helperId: string; inputs: Record<string, unknown> };
        const data = await guardFetch(api, "/v1/authoring/helper/test", "POST", input, {
          "X-Guard-Role": "author",
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_list -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_list",
      label: "Guard Helper List",
      description:
        "List all Guard-managed helpers. Returns helper IDs, names, runtimes, permission " +
        "levels, and approval status. Use to discover existing helpers when editing a scheme.",
      parameters: {
        type: "object",
        properties: {},
        required: [],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async () => {
        const data = await guardFetch(api, "/v1/helpers", "GET");
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_read -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_read",
      label: "Guard Helper Read",
      description:
        "Read a single Guard-managed helper by ID. Returns the full helper spec including " +
        "the entrypoint script loaded from disk, file listing, input schema, permissions, " +
        "and approval status.",
      parameters: {
        type: "object",
        properties: {
          helperId: { type: "string", description: "The helper ID to read." },
        },
        required: ["helperId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { helperId: string };
        const data = await guardFetch(
          api,
          `/v1/authoring/helper?helperId=${encodeURIComponent(input.helperId)}`,
          "GET",
          undefined,
          { "X-Guard-Role": "author" },
        );
        if (!data)
          return jsonResult({ ok: false, error: "Helper not found or Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_write_file -------------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_write_file",
      label: "Guard Helper Write File",
      description:
        "Write a single file into a helper's directory. Use to add supporting modules, " +
        "dependency manifests (requirements.txt, package.json), or data files to an " +
        "existing helper.",
      parameters: {
        type: "object",
        properties: {
          helperId: { type: "string", description: "The helper ID." },
          filename: { type: "string", description: "Filename to write (no path traversal)." },
          content: { type: "string", description: "File content." },
        },
        required: ["helperId", "filename", "content"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { helperId: string; filename: string; content: string };
        const data = await guardFetch(api, "/v1/authoring/helper/file", "POST", input, {
          "X-Guard-Role": "author",
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_helper_install_deps -----------------------------------------------
  api.registerTool(
    {
      name: "guard_helper_install_deps",
      label: "Guard Helper Install Dependencies",
      description:
        "Install dependencies for a helper. For node: npm install --production. " +
        "For python: pip install -r requirements.txt. Call after writing a dependency " +
        "manifest with guard_helper_create or guard_helper_write_file.",
      parameters: {
        type: "object",
        properties: {
          helperId: { type: "string", description: "The helper ID." },
        },
        required: ["helperId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { helperId: string };
        const data = await guardFetch(api, "/v1/authoring/helper/install-deps", "POST", input, {
          "X-Guard-Role": "author",
        });
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult(data);
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );

  // guard_scheme_read -------------------------------------------------------
  api.registerTool(
    {
      name: "guard_scheme_read",
      label: "Guard Scheme Read",
      description:
        "Read the current active Guard authorization scheme for authoring. Optionally filter " +
        "by intentId to get the scheme for a specific intent. Returns the full scheme with " +
        "all rules, exceptions, mode, and metadata. Use this to inspect the current scheme " +
        "before calling guard_scheme_update.",
      parameters: {
        type: "object",
        properties: {
          intentId: {
            type: "string",
            description: "Intent ID to get the scheme for a specific intent.",
          },
          schemeId: {
            type: "string",
            description: "Scheme ID to read a specific scheme.",
          },
        },
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = (params as { intentId?: string; schemeId?: string }) ?? {};
        const intentId = typeof input.intentId === "string" ? input.intentId.trim() : "";
        const schemeId = typeof input.schemeId === "string" ? input.schemeId.trim() : "";
        let path = "/v1/authoring/scheme";
        const queryParts: string[] = [];
        if (schemeId) queryParts.push(`schemeId=${encodeURIComponent(schemeId)}`);
        else if (intentId) queryParts.push(`intentId=${encodeURIComponent(intentId)}`);
        if (queryParts.length > 0) path += `?${queryParts.join("&")}`;
        const data = await guardFetch(api, path, "GET", undefined, {
          "X-Guard-Role": "author",
        });
        if (!data)
          return jsonResult({ ok: false, error: "No active scheme found or Guard unavailable." });
        return jsonResult({ ok: true, scheme: data });
      },
    } as AnyAgentTool,
    guardAuthoringToolOpts,
  );
}

// ---------------------------------------------------------------------------
// Runtime tools -- always available to the guarded agent
//
// SECURITY BOUNDARY: Tools below are visible to the agent being guarded.
// Authoring tools live in registerAuthoringTools() with
// optionalRequiresAllowlistToken: group:guard-authoring so `group:plugins` alone
// does not expose them; only registerRuntimeTools + normal optional policy apply here.
//
// Safe for runtime: guard_helper_run, guard_graph_read, guard_graph_list,
// guard_hold_release, guard_knowledge_test, guard_approval.
// ---------------------------------------------------------------------------

function registerRuntimeTools(api: OpenClawPluginApi) {
  const guardRuntimeToolOpts = { optional: true as const };
  // guard_helper_run --------------------------------------------------------
  // Uses the factory pattern so ctx.sessionKey is injected automatically;
  // the LLM never needs to know or pass the opaque session key.
  api.registerTool(
    (ctx) =>
      ({
        name: "guard_helper_run",
        label: "Guard Helper Run",
        description:
          "Execute a Guard-managed helper and auto-attest the result. The helper's inputs and " +
          "outputs are recorded in the session log for SEQUENCE binding verification. " +
          "Pass the helper ID (or name) and the JSON inputs.",
        parameters: {
          type: "object",
          properties: {
            helperId: { type: "string", description: "Helper ID or name." },
            inputs: { type: "object", description: "JSON inputs to pass to the helper." },
          },
          required: ["helperId", "inputs"],
          additionalProperties: false,
        } as Record<string, unknown>,
        execute: async (_toolCallId: string, params: unknown) => {
          const input = params as { helperId: string; inputs: Record<string, unknown> };
          const sessionKey = ctx.sessionKey ?? "";
          const id = encodeURIComponent(input.helperId);
          const data = await guardFetch(api, `/v1/helpers/${id}/run`, "POST", {
            inputs: input.inputs,
            sessionKey,
          });
          if (!data)
            return jsonResult({ ok: false, error: "Helper not found or Guard unavailable." });
          return jsonResult(data);
        },
      }) as AnyAgentTool,
    guardRuntimeToolOpts,
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
        if (!graphId) return jsonResult({ ok: false, error: "graphId is required." });
        const data = await guardFetch(api, `/v1/graphs/${encodeURIComponent(graphId)}`, "GET");
        if (!data) return jsonResult({ ok: false, error: "Graph not found or Guard unavailable." });
        return jsonResult({ ok: true, graph: data });
      },
    } as AnyAgentTool,
    guardRuntimeToolOpts,
  );

  // guard_graph_list --------------------------------------------------------
  api.registerTool(
    {
      name: "guard_graph_list",
      label: "Guard Graph List",
      description:
        "List all Guard intent knowledge graphs. Returns an array of graphs with their " +
        "graphId, intentId, intentText, modeState, and node/edge counts. " +
        "Use this to discover existing intents when no specific graphId or intentId is known.",
      parameters: {
        type: "object",
        properties: {},
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async () => {
        const data = await guardFetch(api, "/v1/graphs", "GET");
        if (!data) return jsonResult({ ok: false, error: "Guard unavailable." });
        return jsonResult({ ok: true, graphs: data });
      },
    } as AnyAgentTool,
    guardRuntimeToolOpts,
  );

  // guard_knowledge_test ---------------------------------------------------
  api.registerTool(
    (ctx) =>
      ({
        name: "guard_knowledge_test",
        label: "Guard Knowledge Test",
        description:
          "Answer a knowledge test to proceed when a tool is blocked by the Guard knowledge test gate.",
        parameters: {
          type: "object",
          properties: {
            answer: { type: "string", description: "Your answer to the knowledge test question." },
          },
          required: ["answer"],
          additionalProperties: false,
        } as Record<string, unknown>,
        execute: async (_toolCallId: string, params: unknown) => {
          const input = params as { answer?: string };
          if (!input.answer) return jsonResult({ ok: false, error: "answer is required." });
          const decision = await callGuardDecision(api, {
            eventType: "ACTION_EVENT",
            eventId: randomUUID(),
            occurredAt: new Date().toISOString(),
            identity: {
              agentId: ctx.agentId ?? "main",
              sessionKey: ctx.sessionKey ?? "",
              sessionId: ctx.sessionKey ?? "",
            },
            action: { toolName: "guard_knowledge_test", args: { answer: input.answer } },
          });

          if (decision.pendingKnowledgeTest) {
            return jsonResult({
              ok: false,
              error: "Knowledge test failed. " + (decision.remediation?.retryHint || "Try again."),
            });
          }

          return jsonResult({
            ok: true,
            result:
              "Knowledge test passed. You may now retry the exact same tool call that was blocked.",
          });
        },
      }) as AnyAgentTool,
    guardRuntimeToolOpts,
  );

  // guard_hold_release -----------------------------------------------------
  api.registerTool(
    {
      name: "guard_hold_release",
      label: "Guard Hold Release",
      description:
        "Release a Guard hold that was previously approved by the human. Pass the holdId from the " +
        "block reason. Returns the frozen request so you can retry the exact same tool call.",
      parameters: {
        type: "object",
        properties: {
          holdId: { type: "string", description: "The hold ID returned in the block reason." },
        },
        required: ["holdId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { holdId?: string };
        const holdId = typeof input.holdId === "string" ? input.holdId.trim() : "";
        if (!holdId) return jsonResult({ ok: false, error: "holdId is required." });
        const data = await guardFetch(
          api,
          `/v1/holds/${encodeURIComponent(holdId)}/release`,
          "POST",
        );
        if (!data)
          return jsonResult({
            ok: false,
            error: "Hold not found, not yet approved, or Guard unavailable.",
          });
        return jsonResult({ ok: true, ...(data as HoldReleaseResponse) });
      },
    } as AnyAgentTool,
    guardRuntimeToolOpts,
  );

  // guard_hold_status ------------------------------------------------------
  api.registerTool(
    {
      name: "guard_hold_status",
      label: "Guard Hold Status",
      description:
        "Check the current status of a Guard hold. Returns whether it is pending, approved, denied, or released.",
      parameters: {
        type: "object",
        properties: {
          holdId: { type: "string", description: "The hold ID to check." },
        },
        required: ["holdId"],
        additionalProperties: false,
      } as Record<string, unknown>,
      execute: async (_toolCallId: string, params: unknown) => {
        const input = params as { holdId?: string };
        const holdId = typeof input.holdId === "string" ? input.holdId.trim() : "";
        if (!holdId) return jsonResult({ ok: false, error: "holdId is required." });
        const data = await guardFetch(api, `/v1/holds/${encodeURIComponent(holdId)}`, "GET");
        if (!data) return jsonResult({ ok: false, error: "Hold not found or Guard unavailable." });
        return jsonResult({ ok: true, hold: data });
      },
    } as AnyAgentTool,
    guardRuntimeToolOpts,
  );
}

// ---------------------------------------------------------------------------
// Hook registration
//
// before_tool_call: enrich browser actions with cached snapshot state, run
// bootstrap self-protection checks, and evaluate against Guard.
// Guard's own tools (guard_*) are excluded to avoid deadlocks.
// Snapshot-only actions are skipped to reduce latency.
//
// If Guard returns a holdId, the agent is told how to get approval and retry.
// If it returns unauthorized without a hold, the action is simply blocked.
// -------------------------------------------------------------------------
const GUARD_TOOL_PREFIX = "guard_";

export function registerGuardPlugin(api: OpenClawPluginApi) {
  registerRuntimeTools(api);
  registerAuthoringTools(api);

  // Authoring session manager + gateway methods + HTTP routes
  const cfg = resolveConfig(api);
  const authoringManager = new AuthoringSessionManager(api, cfg.endpoint);
  registerAuthoringGateway(api, authoringManager);
  registerAuthoringHttpHandler(api, authoringManager);

  // -------------------------------------------------------------------------
  // before_tool_call: enrich, protect, evaluate
  // -------------------------------------------------------------------------
  api.on("before_tool_call", async (event, ctx) => {
    if (event.toolName.startsWith(GUARD_TOOL_PREFIX)) {
      return undefined;
    }

    // Skip Guard evaluation for read-only snapshot actions to avoid adding
    // latency to every snapshot → click → snapshot cycle.
    if (isSnapshotTool(event.toolName, (event.params ?? {}) as Record<string, unknown>)) {
      return undefined;
    }

    const bootstrapReason = bootstrapBlock(event.toolName, event.params);
    if (bootstrapReason) {
      return { block: true, blockReason: bootstrapReason };
    }

    const sessionKey = ctx.sessionKey ?? "";

    let guardAction: { toolName: string; args: Record<string, unknown> } = {
      toolName: event.toolName,
      args: event.params ?? {},
    };

    // Enrich browser actions with cached snapshot state (element names,
    // URLs, nearby context, page elements, JS expressions).
    if (event.toolName === "browser" && event.params) {
      const enriched = enrichBrowserAction(event.params);
      if (enriched) guardAction = enriched;
    } else if (event.toolName.startsWith("browser_") && event.toolName !== "browser_snapshot") {
      guardAction = { toolName: event.toolName, args: enrichDirectBrowserTool(event.params ?? {}) };
    }

    const decision = await callGuardDecision(api, {
      eventType: "ACTION_EVENT",
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      identity: {
        agentId: ctx.agentId ?? "main",
        sessionKey,
        sessionId: sessionKey,
      },
      action: guardAction,
    });

    if (decision.authorized === false) {
      if (decision.holdId) {
        const holdId = decision.holdId;
        const violations = (decision.violations ?? [])
          .map((v) => v.reason)
          .filter(Boolean)
          .join("; ");

        return {
          block: true,
          blockReason:
            `Guard hold ${holdId} created — this ${event.toolName} call requires human approval. ` +
            `Violations: ${violations || "policy violation detected"}. ` +
            `The human can approve via the Guard dashboard at http://127.0.0.1:4520 ` +
            `or by typing /guard-approve ${holdId} in any OpenClaw channel. ` +
            `Once approved, call guard_hold_release with holdId "${holdId}" to get the frozen request, ` +
            `then retry the EXACT same tool call — Guard will recognize it and allow it through.`,
        };
      }

      if (decision.pendingKnowledgeTest) {
        const violations = (decision.violations ?? [])
          .map((v) => v.reason)
          .filter(Boolean)
          .join("; ");

        return {
          block: true,
          blockReason:
            `Guard knowledge test required — this ${event.toolName} call requires you to prove understanding. ` +
            `Violations: ${violations || "policy violation detected"}. ` +
            `Question: "${decision.knowledgeTestQuestion}". ` +
            `Answer using the guard_knowledge_test tool. Once passed, retry the EXACT same tool call.`,
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
  // after_tool_call: cache snapshot state from browser results and forward
  // enriched snapshots to Guard. The hook fires twice per tool call — we
  // only report if the new snapshot is at least as rich as the previous one.
  // -------------------------------------------------------------------------
  api.on("after_tool_call", async (event) => {
    if (!event.toolName.startsWith("browser")) return;

    const prevRefCount = Object.keys(getBrowserState().refs).length;
    updateBrowserStateFromResult(event.toolName, event.params ?? {}, event.result);
    const newRefCount = Object.keys(getBrowserState().refs).length;

    if (resultHasSnapshot(event.result) && newRefCount >= prevRefCount) {
      // snapshot data is now tracked by the browser state cache only
    }
  });

  // -------------------------------------------------------------------------
  // message_sending: evaluate every outbound channel message against Guard.
  // -------------------------------------------------------------------------
  api.on("message_sending", async (event, ctx) => {
    const decision = await callGuardDecision(api, {
      eventType: "CHANNEL_EVENT",
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      identity: {
        agentId: "main",
        sessionKey: ctx.conversationId ?? "",
        sessionId: ctx.conversationId,
        channelId: ctx.channelId,
        accountId: ctx.accountId,
      },
      channel: {
        text: event.content ?? "",
      },
    });

    if (decision.authorized === false) {
      const feedback = toBoundedFeedback(decision);
      return {
        content: `Guard blocked channel message. ${feedback}`,
      };
    }
    return undefined;
  });

  // -------------------------------------------------------------------------
  // gateway method: guard.hold.resolve
  // Called by the Guard UI dashboard or connected clients to approve/deny.
  // -------------------------------------------------------------------------
  api.registerGatewayMethod("guard.hold.resolve", async ({ params, respond, context }) => {
    const holdId = typeof params.holdId === "string" ? params.holdId : "";
    const decision = params.decision === "deny" ? "deny" : "allow";
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
      const decision = decisionArg === "deny" ? "deny" : "allow";

      if (!holdId) {
        return { text: "Usage: /guard-approve <holdId> [allow|deny]" };
      }

      const cfg = resolveConfig(api);
      const action = decision === "allow" ? "approve" : "deny";
      try {
        const resp = await fetch(`${cfg.endpoint}/v1/holds/${holdId}/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            approvedBy: (ctx as Record<string, unknown>).userId ?? "command",
          }),
          signal: AbortSignal.timeout(cfg.timeoutMs),
        });
        if (!resp.ok) {
          return { text: `Guard hold ${action} failed: HTTP ${resp.status}` };
        }
      } catch (err) {
        return { text: `Guard hold ${action} failed: ${String(err)}` };
      }

      return { text: `Guard hold ${holdId} ${action === "approve" ? "approved" : "denied"}.` };
    },
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
