import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import os from "node:os";
import path from "node:path";
import type { OpenClawPluginApi } from "../../../src/plugins/types.js";
import { GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN } from "./authoring-allowlist-token.js";

// ---------------------------------------------------------------------------
// Dynamic internal imports (same pattern as llm-task)
// ---------------------------------------------------------------------------

type RunEmbeddedPiAgentFn = (params: Record<string, unknown>) => Promise<unknown>;

async function loadRunEmbeddedPiAgent(): Promise<RunEmbeddedPiAgentFn> {
  try {
    const mod = await import("../../../src/agents/pi-embedded-runner.js");
    if (typeof (mod as Record<string, unknown>).runEmbeddedPiAgent === "function") {
      return (mod as Record<string, unknown>).runEmbeddedPiAgent as RunEmbeddedPiAgentFn;
    }
  } catch {
    // ignore
  }
  const mod = await import("../../../src/agents/pi-embedded-runner.js");
  if (typeof mod.runEmbeddedPiAgent !== "function") {
    throw new Error("Internal error: runEmbeddedPiAgent not available");
  }
  return mod.runEmbeddedPiAgent as RunEmbeddedPiAgentFn;
}

type CoreToolSection = {
  id: string;
  label: string;
  tools: Array<{ id: string; label: string; description: string }>;
};

type ToolCatalogEntry = {
  name: string;
  section: string;
  description: string;
  parameters?: unknown;
};

// ---------------------------------------------------------------------------
// Phase 1: Tool Catalog Resolution
// ---------------------------------------------------------------------------

export async function resolveAuthoringToolCatalog(
  api: OpenClawPluginApi,
): Promise<{ entries: ToolCatalogEntry[]; formatted: string }> {
  const { listCoreToolSections } = (await import("../../../src/agents/tool-catalog.js")) as {
    listCoreToolSections: () => CoreToolSection[];
  };

  const sections = listCoreToolSections();

  // Attempt to get parameter schemas for core tools via createOpenClawCodingTools.
  // This may fail in some contexts (missing sandbox, etc.) -- fall back gracefully.
  let coreToolSchemas = new Map<string, unknown>();
  try {
    const { createOpenClawCodingTools } = (await import("../../../src/agents/pi-tools.js")) as {
      createOpenClawCodingTools: (opts?: Record<string, unknown>) => Array<{
        name: string;
        parameters?: unknown;
      }>;
    };
    const tools = createOpenClawCodingTools({
      workspaceDir: api.config?.agents?.defaults?.workspace ?? process.cwd(),
      config: api.config,
    });
    for (const tool of tools) {
      if (tool.parameters) {
        coreToolSchemas.set(tool.name, tool.parameters);
      }
    }
  } catch {
    // Core tool schemas are nice-to-have; catalog still works with names + descriptions
  }

  // Resolve plugin tools for schemas
  let pluginToolEntries: ToolCatalogEntry[] = [];
  try {
    const mod = await import("../../../src/plugins/tools.js");
    const pluginTools = mod.resolvePluginTools({
      context: {
        config: api.config,
        workspaceDir: api.config?.agents?.defaults?.workspace ?? process.cwd(),
      },
      existingToolNames: new Set(sections.flatMap((s) => s.tools.map((t) => t.id))),
      toolAllowlist: ["group:plugins"],
      suppressNameConflicts: true,
    });
    pluginToolEntries = pluginTools
      .filter((t) => !t.name.startsWith("guard_"))
      .map((t) => ({
        name: t.name,
        section: "plugins",
        description: t.description ?? t.label ?? t.name,
        parameters: t.parameters,
      }));
  } catch {
    // Plugin tools are nice-to-have
  }

  // Build core entries, merging schemas where available
  const coreEntries: ToolCatalogEntry[] = [];
  for (const section of sections) {
    for (const tool of section.tools) {
      if (tool.id.startsWith("guard_")) continue;
      coreEntries.push({
        name: tool.id,
        section: section.label,
        description: tool.description,
        parameters: coreToolSchemas.get(tool.id),
      });
    }
  }

  const allEntries = [...coreEntries, ...pluginToolEntries];

  // Format as readable text for the system prompt
  const formatted = formatToolCatalog(coreEntries, pluginToolEntries, sections);
  return { entries: allEntries, formatted };
}

function formatToolCatalog(
  coreEntries: ToolCatalogEntry[],
  pluginEntries: ToolCatalogEntry[],
  sections: CoreToolSection[],
): string {
  const lines: string[] = [
    "## Available Tools",
    "",
    "Use these tool names in toolFilter and requiredTools fields. These are the tools the guarded agent has access to.",
    "",
  ];

  // Group core entries by section
  const sectionMap = new Map<string, ToolCatalogEntry[]>();
  for (const entry of coreEntries) {
    const list = sectionMap.get(entry.section) ?? [];
    list.push(entry);
    sectionMap.set(entry.section, list);
  }

  for (const section of sections) {
    const entries = sectionMap.get(section.label);
    if (!entries || entries.length === 0) continue;
    lines.push(`### ${section.label}`);
    for (const entry of entries) {
      const paramSummary = entry.parameters
        ? ` — Parameters: ${summarizeParams(entry.parameters)}`
        : "";
      lines.push(`- \`${entry.name}\`: ${entry.description}${paramSummary}`);
    }
    lines.push("");
  }

  if (pluginEntries.length > 0) {
    lines.push("### Plugin Tools");
    for (const entry of pluginEntries) {
      const paramSummary = entry.parameters
        ? ` — Parameters: ${summarizeParams(entry.parameters)}`
        : "";
      lines.push(`- \`${entry.name}\`: ${entry.description}${paramSummary}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function summarizeParams(params: unknown): string {
  if (!params || typeof params !== "object") return "{}";
  const schema = params as Record<string, unknown>;
  const props = schema.properties as Record<string, unknown> | undefined;
  if (!props) return "{}";
  const keys = Object.keys(props).slice(0, 8);
  const summary = keys
    .map((k) => {
      const prop = props[k] as Record<string, unknown> | undefined;
      const type = prop?.type ?? "unknown";
      return `${k}: ${type}`;
    })
    .join(", ");
  const more = Object.keys(props).length > 8 ? ", ..." : "";
  return `{ ${summary}${more} }`;
}

// ---------------------------------------------------------------------------
// Phase 2: Authoring System Prompt
// ---------------------------------------------------------------------------

type AuthoringPromptParams = {
  mode: "create" | "edit";
  intentId?: string;
  graphId?: string;
  scheme?: unknown;
  toolCatalog: string;
};

export function buildAuthoringSystemPrompt(params: AuthoringPromptParams): string {
  const parts: string[] = [];

  parts.push(`# Guard Scheme Authoring Agent

You are an expert AI agent specializing in authoring Guard authorization schemes for other AI agents. Your task is to convert a user's security intent into a formally structured Guard scheme configuration. You have expert statistical reasoning as well, which helps you build semantic authorization schemes that work in a balanced way.

## Your Tools

You can ONLY call guard_* tools. Do NOT call any other tools (no sessions_list, no file tools, no browser tools, etc.). The tool catalog below is reference material showing what tools the GUARDED AGENT has — it is NOT your tool list.

IMPORTANT: The "Guard Tool Signatures" section below contains the exact JSON parameter schemas for guard_* tools. Follow those schemas exactly when calling tools.

Your available tools:
- \`guard_introspect\`: Get the full rule type specification. Call this first if you need to understand rule types, required fields, or composition patterns.
- \`guard_graph_list\`: List all existing knowledge graphs. Returns graphId, intentId, intentText for each. Use this to discover available intents when no specific ID is known.
- \`guard_graph_read\`: Read an existing knowledge graph by graphId. Use this to understand the intent structure before drafting rules.
- \`guard_graph_save\`: Save a knowledge graph that maps user intent to risk surfaces. Nodes must include stable nodeId values so edges can reference source/target correctly.
- \`guard_scheme_read\`: Read the current active authorization scheme. Optionally pass an intentId to get the scheme for a specific intent. Use this to review existing rules before editing.
- \`guard_validate_rule\`: Validate a single rule before adding it to a scheme. Fix all errors before proceeding.
- \`guard_validate_scheme\`: Validate a complete scheme (array of rules) for correctness and composition quality.
- \`guard_simulate\`: Test draft rules against sample events to verify detection accuracy. Test both events that should be blocked AND events that should pass.
- \`guard_compile_scheme\`: Compile and activate a validated scheme. Only call after validation and simulation pass.
- \`guard_helper_create\`: Create or update a Guard-managed helper. Each helper is a directory on disk that persists state between runs. Can provide script directly, or set stub:true for complex helpers the user will implement.
- \`guard_helper_test\`: Test a helper with sample inputs before compiling the scheme. Runs without attestation.
- \`guard_helper_list\`: List all existing Guard-managed helpers. Use to discover helpers when editing an existing scheme.
- \`guard_helper_read\`: Read a single helper by ID. Returns script loaded from disk, file listing, input schema, and permissions.
- \`guard_helper_write_file\`: Write a file into a helper's directory (supporting modules, dependency manifests, data files).
- \`guard_helper_install_deps\`: Install dependencies for a helper (npm install / pip install).

Current canonical rule types are: SYNTAX, SEMANTICS, SEQUENCE, SEMANTICS_SEQUENCE, and SENSITIVE_DATA.

## Rule-Level and Scheme-Level Codegates

Any rule can include an optional \`codeGate\` field containing a Starlark script. The script returns true to auto-allow (bypasses that rule's violation), false to escalate to exceptions/approval/denial. Use for rate limiting, time-of-day restrictions, progressive trust, cooldowns, or filtering specific targets.

Example rule-level codeGate:
\`\`\`json
{
  "codeGate": {
    "script": "count = state.get('call_count', 0) + 1\\nstate.set('call_count', count)\\ncount <= 3",
    "description": "Allow up to 3 calls per session"
  }
}
\`\`\`

Scheme-level exceptions (submitted via \`guard_compile_scheme\` \`exceptions\` field) work similarly but apply across ALL rules — use for admin bypass or maintenance windows.

Refer to the Guard Rule Type Specification below for full codeGate builtins (state, time, event, violations).

## When to Use Helpers vs. Starlark Codegates

**Use Starlark codegate (NOT a helper) for:**
- Simple pattern matching (regex on tool args)
- Small static lists (email whitelist with <20 entries)
- Pure logic on the current tool call's arguments
- Anything stateless that can be expressed in a few lines
- Rate limiting, time-of-day, cooldowns (codeGate has state and time builtins)

**Use a helper for:**
- **Stateful logic**: tracking cumulative spend, counting calls, maintaining a running log. Helpers persist state in their directory between runs.
- **Complex validation**: checking data against an external API, running embeddings, querying a database.
- **Dependencies**: anything requiring npm packages, pip packages, or external libraries.

## Guard Helper Workflow

### Simple helpers (you can write the full script)

1. Use \`guard_helper_create\` with name, runtime, and script. The script reads JSON from stdin and writes JSON to stdout. Use \`files\` to include dependency manifests (requirements.txt, package.json) or supporting modules.
2. If dependencies were provided, call \`guard_helper_install_deps\`.
3. Test with \`guard_helper_test\` using realistic inputs.
4. In the SEQUENCE rule: reference \`guard_helper:<name>\` in requiredTools.
5. Use \`bindings\` to tie helper input/output to the gated tool's args.
6. Use \`requiredOutput\` to assert the helper returned success.

### Complex helpers (beyond your capability)

When the helper requires database access, ML models, complex external API integrations, or substantial business logic:

1. Use \`guard_helper_create\` with stub:true, providing name, runtime, description, and inputSchema.
2. The sidecar scaffolds a directory with a stub entrypoint and README explaining the contract (expected inputs/outputs).
3. Use \`guard_helper_write_file\` to add a requirements.txt or package.json listing the dependencies you know are needed.
4. Wire the SEQUENCE rule with the correct bindings — you know the input/output contract even if you can't write the implementation.
5. Tell the user: "I've created a stub helper at ~/.config/guard/helpers/<name>/. Please implement the logic in main.py. See the README for the contract."

### Examples

**Spend tracking** (stateful, simple script):
- Helper: track_daily_spend (reads {amount}, writes to local spend.json, returns {withinBudget, remaining})
- SEQUENCE: requiredTools=["guard_helper:track_daily_spend"], gateTools=["make_purchase"]
- RequiredOutput: {"withinBudget": true}

**Citation validation** (complex, stub):
- Helper: validate_citation (needs tavily-python, ollama, numpy — stub:true)
- InputSchema: {url: "URL to validate", claim: "Claim to verify against URL content"}
- SEQUENCE: requiredTools=["guard_helper:validate_citation"], gateTools=["submit_research"]
- RequiredOutput: {"valid": true}

## Workflow

1. **Understand the user's intent.** Ask clarifying questions if the intent is ambiguous. What behaviors should be allowed? What should be blocked?
2. **Read existing context.** If editing or the user provides a graph/intent ID, use \`guard_graph_read\` to understand the current graph structure. Check existing helpers with \`guard_helper_list\`.
3. **Inventory tools.** Review the tool catalog below to understand what tools the guarded agent has. Use exact tool names in toolFilter and requiredTools fields.
4. **Build a knowledge graph** using \`guard_graph_save\` to map the intent to risk surfaces.
5. **Draft rules.** Choose appropriate rule types for each risk domain. Use Starlark codegates for simple per-call logic. Validate each rule individually with \`guard_validate_rule\`.
6. **Create helpers** if any SEQUENCE rules need stateful or complex verification. Use \`guard_helper_create\` (with script or stub:true) and \`guard_helper_test\`.
7. **Validate the complete scheme** with \`guard_validate_scheme\`. Fix any errors or warnings.
8. **Simulate** with \`guard_simulate\` using realistic sample events — include both events that should be blocked AND events that should pass. Adjust rules based on results.
9. **Iterate.** Repeat validation and simulation until the scheme is solid. Do not rush to compile.
10. **Compile** with \`guard_compile_scheme\` only when you and the user are satisfied.

## Important Guidelines

- ONLY use guard_* tools. You do not have access to any other tools.
- Always validate before compiling. Never skip validation.
- Use simulation to test for false positives on safe operations.
- Confirm with the user before compiling, unless they have already approved or asked for no confirmations.
- When writing elaboration text for SEMANTICS rules, be specific and grounded. Avoid vague language.
- When writing denyPattern for SYNTAX rules, test patterns against realistic tool arguments.
- For SEQUENCE rules, verify the required tool order makes sense for the user's workflow.

## Execution Style (Critical)

- Be execution-first, not confirmation-first. Act like a senior engineer pair-programming, not a chatbot.
- If the user request is actionable, call guard_* tools in the SAME turn. NEVER stop at "I can do that" or "ready when you are."
- NEVER say "I'll do X in the next turn." There is no next turn — do it NOW.
- Keep narration to one brief sentence per step. Lead with tool calls, follow with a short status line.
- Ask questions only when required information is genuinely missing from the conversation.
- Never claim you cannot execute guard_* tools. You CAN. Attempt the calls; if one fails, report the exact error.
- When the user says "yes", "ok", "approved", "do it", "go ahead" — that IS confirmation. Execute immediately.
- If the user says "no confirmations" or "don't ask", skip ALL confirmation prompts including before compile.
`);

  if (params.mode === "edit" && params.scheme) {
    const editContext: string[] = [
      `## Current Scheme (Edit Mode)

You are editing an existing scheme. Review the current rules carefully before proposing changes. Preserve rules the user hasn't asked to modify.`,
    ];

    if (params.intentId || params.graphId) {
      editContext.push("");
      editContext.push(
        "**IMPORTANT — These IDs are already resolved for this session. Use them directly in tool calls (guard_graph_read, guard_compile_scheme, etc.). Do NOT ask the user for IDs.**",
      );
      if (params.intentId) editContext.push(`- intentId: \`${params.intentId}\``);
      if (params.graphId) editContext.push(`- graphId: \`${params.graphId}\``);
      editContext.push("");
    }

    editContext.push(`\`\`\`json
${JSON.stringify(params.scheme, null, 2)}
\`\`\``);

    parts.push(editContext.join("\n"));
  } else {
    parts.push(`## New Scheme (Create Mode)

You are creating a new scheme from scratch. You HAVE full access to all guard_* tools and MUST use them. They are available as callable tools in this session — call them directly.

Follow the full workflow: understand intent → call \`guard_introspect\` → build knowledge graph → draft rules → validate → simulate → compile.

Start by calling \`guard_introspect\` to get the current rule specification, then proceed with tool calls immediately. Do NOT output a JSON payload for the user to "paste" — that is never acceptable. YOU call the tools.

If the user asks to work with an existing intent or fix a broken scheme, call \`guard_graph_list\` to discover available graphs, then \`guard_scheme_read\` with the intentId to load the existing scheme.
`);
  }

  parts.push(params.toolCatalog);
  parts.push("");

  parts.push(`## Guard Rule Type Specification

Do NOT rely on memorized rule schemas. Call \`guard_introspect\` at the start of any authoring session to get the exact, current rule type specification including required fields, composition patterns, and anti-patterns. The introspection spec is authoritative — always defer to it over any prior knowledge.
`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Phase 3: Authoring Session Manager
// ---------------------------------------------------------------------------

type AuthoringSession = {
  sessionId: string;
  mode: "create" | "edit";
  intentId?: string;
  graphId?: string;
  tempDir: string;
  sessionFile: string;
  toolCatalog: string;
  currentScheme?: unknown;
  createdAt: number;
  lastActiveAt: number;
};

type StreamCallback = (payload: {
  type: "text" | "tool_call" | "tool_result" | "done" | "error";
  data: unknown;
}) => void;

const AUTHORING_SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const AUTHORING_TIMEOUT_MS = 180_000; // 3 minutes per turn
// ---------------------------------------------------------------------------
// Agentic continuation loop
//
// Decision logic uses tool calls as the primary signal, not text heuristics.
//   - Turn produced tool calls (but not guard_compile_scheme) → continue.
//   - Turn produced guard_compile_scheme (success) → stop.
//   - Turn produced guard_compile_scheme (failure) → fix and retry.
//   - Turn produced NO tool calls + agent is stalling → retry once.
//   - Turn produced NO tool calls + agent is yielding to user → stop.
// ---------------------------------------------------------------------------

const AUTHORING_MAX_ITERATIONS = 8;
const AUTHORING_MAX_NO_TOOL_RETRIES = 2;

const AUTHORING_CONTINUE_PROMPT =
  "Continue executing. Call the next required guard_* tool now. " +
  "Do not narrate, plan, or ask for confirmation — execute.";

const AUTHORING_RETRY_PROMPT =
  "You did not call any guard_* tools in the previous turn. " +
  "This is an authoring session — you HAVE guard_* tools and MUST use them. " +
  "Do NOT output JSON for the user to paste. Do NOT say you 'can't execute' or lack access. " +
  "You have full tool access RIGHT NOW. " +
  "Execute the required tool calls NOW. Do not refuse, do not say NO_REPLY, " +
  "do not claim inability. Call guard_* tools and report results.";

const AUTHORING_COMPILE_FAILED_PROMPT =
  "guard_compile_scheme failed. Fix the errors reported by the compiler: " +
  "adjust the rules, re-validate with guard_validate_scheme, then call guard_compile_scheme again. " +
  "Do not stop to report the failure — fix and retry now.";

function isActionableUserMessage(message: string): boolean {
  const lower = message.toLowerCase().trim();
  if (!lower || lower.length > 500) return false;
  const questionOnly = /^[^.!]*\?$/.test(lower) && !lower.includes("can you");
  if (questionOnly) return false;
  const signals = [
    "improve",
    "update",
    "fix",
    "validate",
    "simulate",
    "compile",
    "make the scheme",
    "apply",
    "run",
    "keep going",
    "continue",
    "yes",
    "ok",
    "approved",
    "go ahead",
    "proceed",
    "do it",
    "make the changes",
    "get it done",
    "just do it",
  ];
  return signals.some((s) => lower.includes(s));
}

function isAgentYieldingToUser(text: string): boolean {
  const lower = text.toLowerCase();

  const refusalSignals = [
    "can't execute",
    "cannot execute",
    "i can't",
    "i cannot",
    "not able to",
    "unable to execute",
    "no_reply",
    "i'm sorry",
    "don't have access",
    "do not have access",
    "this chat context",
    "this exact chat",
    "ready-to-apply",
    "ready to apply",
    "paste into",
    "paste this",
    "here's the",
    "here is the",
  ];
  if (refusalSignals.some((s) => lower.includes(s))) return false;

  const yieldSignals = [
    "confirm",
    "would you like",
    "do you want",
    "shall i",
    "ready to compile",
    "before i compile",
    "go/no-go",
    "approve",
    "let me know",
  ];
  return yieldSignals.some((s) => lower.includes(s));
}

export class AuthoringSessionManager {
  private sessions = new Map<string, AuthoringSession>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private api: OpenClawPluginApi;
  private guardEndpoint: string;
  private runAgent: RunEmbeddedPiAgentFn | null = null;
  private resolvedAgentId = "main";

  constructor(api: OpenClawPluginApi, guardEndpoint: string) {
    this.api = api;
    this.guardEndpoint = guardEndpoint;
    this.resolveAgentId();
    this.startCleanup();
  }

  private async resolveAgentId() {
    try {
      const { resolveDefaultAgentId } = await import("../../../src/agents/agent-scope.js");
      this.resolvedAgentId = resolveDefaultAgentId(this.api.config ?? {});
    } catch {
      // Fall back to "main"
    }
  }

  private startCleanup() {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, session] of this.sessions) {
        if (now - session.lastActiveAt > AUTHORING_SESSION_TTL_MS) {
          this.destroySession(id).catch(() => {});
        }
      }
    }, CLEANUP_INTERVAL_MS);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  private async ensureAgent(): Promise<RunEmbeddedPiAgentFn> {
    if (!this.runAgent) {
      this.runAgent = await loadRunEmbeddedPiAgent();
    }
    return this.runAgent;
  }

  private async guardFetch(
    path: string,
    method: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<unknown | null> {
    try {
      const resp = await fetch(`${this.guardEndpoint}${path}`, {
        method,
        headers: {
          ...(body ? { "Content-Type": "application/json" } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(10_000),
      });
      if (!resp.ok) return null;
      return await resp.json();
    } catch {
      return null;
    }
  }

  async startSession(params: {
    mode: "create" | "edit";
    intentId?: string;
  }): Promise<{ sessionId: string; mode: string; currentScheme?: unknown }> {
    const sessionId = `guard-authoring-${randomUUID()}`;
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "guard-authoring-"));
    const sessionFile = path.join(tempDir, "session.json");

    // Resolve tool catalog (guarded agent's tools — NOT guard_* tools, which are function-calling tools)
    const { formatted: toolCatalog } = await resolveAuthoringToolCatalog(this.api);

    // Verify guard_* tools are available as callable function tools (diagnostic)
    try {
      const mod = await import("../../../src/plugins/tools.js");
      const pluginTools = mod.resolvePluginTools({
        context: {
          config: this.api.config,
          workspaceDir: this.api.config?.agents?.defaults?.workspace ?? process.cwd(),
        },
        existingToolNames: new Set<string>(),
        toolAllowlist: ["group:plugins"],
        suppressNameConflicts: true,
      });
      const guardToolNames = pluginTools
        .filter((t) => t.name.startsWith("guard_"))
        .map((t) => t.name);
      console.log(
        `[guard-authoring] session=${sessionId} mode=${params.mode} guard_tools_available=${guardToolNames.length} tools=[${guardToolNames.join(",")}]`,
      );
      if (guardToolNames.length === 0) {
        console.warn(
          "[guard-authoring] WARNING: No guard_* tools resolved as callable function tools. " +
            "Ensure 'group:plugins' is in the tool policy (config.tools.allow or agent.tools.allow).",
        );
      }
    } catch (err) {
      console.warn("[guard-authoring] Could not verify guard tool availability:", err);
    }

    // Fetch current scheme and resolve graphId if editing
    let currentScheme: unknown | undefined;
    let graphId: string | undefined;
    if (params.mode === "edit") {
      const schemePath = params.intentId
        ? `/v1/authoring/scheme?intentId=${encodeURIComponent(params.intentId)}`
        : "/v1/authoring/scheme";
      currentScheme =
        (await this.guardFetch(schemePath, "GET", undefined, {
          "X-Guard-Role": "author",
        })) ?? undefined;

      const resolveIntentId =
        params.intentId ??
        ((currentScheme as Record<string, unknown> | undefined)?.intentId as string | undefined);
      if (resolveIntentId) {
        const graphs = (await this.guardFetch("/v1/graphs", "GET")) as Array<{
          graphId?: string;
          intentId?: string;
        }> | null;
        if (graphs) {
          const match = graphs.find((g) => g.intentId === resolveIntentId);
          if (match?.graphId) graphId = match.graphId;
        }
      }
    }

    const session: AuthoringSession = {
      sessionId,
      mode: params.mode,
      intentId: params.intentId,
      graphId,
      tempDir,
      sessionFile,
      toolCatalog,
      currentScheme,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
    };

    this.sessions.set(sessionId, session);

    return {
      sessionId,
      mode: params.mode,
      currentScheme,
    };
  }

  async sendMessage(
    sessionId: string,
    message: string,
    onStream?: StreamCallback,
  ): Promise<{ text: string; error?: string }> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { text: "", error: "Session not found or expired." };
    }

    session.lastActiveAt = Date.now();
    const runAgent = await this.ensureAgent();

    const systemPrompt = buildAuthoringSystemPrompt({
      mode: session.mode,
      intentId: session.intentId,
      graphId: session.graphId,
      scheme: session.currentScheme,
      toolCatalog: session.toolCatalog,
    });

    const defaultsModel = this.api.config?.agents?.defaults?.model;
    const primary =
      typeof defaultsModel === "string"
        ? defaultsModel.trim()
        : (((defaultsModel as Record<string, unknown>)?.primary as string)?.trim() ?? undefined);
    const provider = primary ? primary.split("/")[0] : undefined;
    const model = primary ? primary.split("/").slice(1).join("/") : undefined;

    const runSingleTurn = async (
      prompt: string,
    ): Promise<{
      finalText: string;
      toolCalls: number;
      toolNames: string[];
      compileSucceeded: boolean;
    }> => {
      let lastEmittedLength = 0;
      let toolCalls = 0;
      const toolNames: string[] = [];
      let compileSucceeded = false;

      const result = (await runAgent({
        sessionId: session.sessionId,
        sessionKey: `agent:${this.resolvedAgentId}:${session.sessionId}`,
        sessionFile: session.sessionFile,
        workspaceDir: this.api.config?.agents?.defaults?.workspace ?? process.cwd(),
        config: this.api.config,
        prompt,
        extraSystemPrompt: systemPrompt,
        timeoutMs: AUTHORING_TIMEOUT_MS,
        runId: `guard-authoring-${Date.now()}`,
        provider,
        model,
        disableTools: false,
        pluginToolAllowlistExtras: [GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
        onPartialReply: (payload: { text?: string }) => {
          if (payload.text && payload.text.length > lastEmittedLength) {
            const delta = payload.text.slice(lastEmittedLength);
            lastEmittedLength = payload.text.length;
            onStream?.({
              type: "text",
              data: { text: delta },
            });
          }
        },
        onAgentEvent: (evt: { stream: string; data: Record<string, unknown> }) => {
          if (evt.stream !== "tool") return;
          const phase = evt.data.phase as string;
          const toolName = (evt.data.name as string) ?? "unknown";
          if (phase === "start") {
            toolCalls += 1;
            toolNames.push(toolName);
            onStream?.({
              type: "tool_call",
              data: { tool: toolName, args: evt.data.args ?? {} },
            });
          } else if (phase === "result") {
            const isError = evt.data.isError === true;
            onStream?.({
              type: "tool_result",
              data: {
                tool: toolName,
                result: evt.data.meta ?? {},
                isError,
              },
            });
            if (toolName === "guard_compile_scheme" && !isError) {
              compileSucceeded = true;
            }
          }
        },
      })) as Record<string, unknown>;

      let finalText = "";
      const payloads = result.payloads as Array<{ text?: string; isError?: boolean }> | undefined;
      if (payloads) {
        finalText = payloads
          .filter((p) => !p.isError && typeof p.text === "string")
          .map((p) => p.text ?? "")
          .join("\n")
          .trim();
      }

      return { finalText, toolCalls, toolNames, compileSucceeded };
    };

    try {
      let finalText = "";
      let totalToolCalls = 0;
      let noToolRetries = 0;
      let prompt = message;
      const actionable = isActionableUserMessage(message);

      for (let iter = 0; iter < AUTHORING_MAX_ITERATIONS; iter += 1) {
        const turn = await runSingleTurn(prompt);
        finalText = turn.finalText || finalText;
        totalToolCalls += turn.toolCalls;

        if (turn.toolNames.includes("guard_compile_scheme")) {
          if (turn.compileSucceeded) {
            break;
          }
          noToolRetries = 0;
          prompt = AUTHORING_COMPILE_FAILED_PROMPT;
          continue;
        }

        if (turn.toolCalls > 0) {
          noToolRetries = 0;
          prompt = AUTHORING_CONTINUE_PROMPT;
          continue;
        }

        // No tool calls this turn — decide: retry or yield to user.
        // Yield only on legitimate questions to the user (compile confirmation, etc.)
        // Everything else (refusals, empty, stalls, "NO_REPLY") gets retried.
        if (isAgentYieldingToUser(turn.finalText)) {
          break;
        }

        if (actionable && noToolRetries < AUTHORING_MAX_NO_TOOL_RETRIES) {
          noToolRetries += 1;
          prompt = AUTHORING_RETRY_PROMPT;
          continue;
        }

        break;
      }

      if (totalToolCalls === 0 && actionable) {
        const errorMsg =
          "Authoring agent stalled: no guard_* tools were called despite an actionable request.";
        onStream?.({ type: "error", data: { error: errorMsg } });
        return { text: "", error: errorMsg };
      }

      onStream?.({ type: "done", data: { text: finalText } });
      return { text: finalText };
    } catch (err) {
      const errorMsg = `Authoring agent error: ${String(err)}`;
      onStream?.({ type: "error", data: { error: errorMsg } });
      return { text: "", error: errorMsg };
    }
  }

  async cancelSession(sessionId: string): Promise<boolean> {
    return this.destroySession(sessionId);
  }

  private async destroySession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    this.sessions.delete(sessionId);
    try {
      await fs.rm(session.tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup failures
    }
    return true;
  }

  getSession(sessionId: string): AuthoringSession | undefined {
    return this.sessions.get(sessionId);
  }

  dispose() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const [id] of this.sessions) {
      this.destroySession(id).catch(() => {});
    }
  }
}

// ---------------------------------------------------------------------------
// Phase 4: Gateway Method Registration
// ---------------------------------------------------------------------------

export function registerAuthoringGateway(api: OpenClawPluginApi, manager: AuthoringSessionManager) {
  api.registerGatewayMethod("guard.authoring.start", async ({ params, respond }) => {
    const mode =
      typeof params.mode === "string" && (params.mode === "create" || params.mode === "edit")
        ? params.mode
        : "create";
    const intentId = typeof params.intentId === "string" ? params.intentId : undefined;

    try {
      const result = await manager.startSession({ mode, intentId });
      respond(true, result, undefined);
    } catch (err) {
      respond(false, undefined, {
        message: `Failed to start authoring session: ${String(err)}`,
        code: "AUTHORING_START_FAILED",
      });
    }
  });

  api.registerGatewayMethod("guard.authoring.message", async ({ params, respond, context }) => {
    const sessionId = typeof params.sessionId === "string" ? params.sessionId : "";
    const message = typeof params.message === "string" ? params.message : "";

    if (!sessionId || !message) {
      respond(false, undefined, {
        message: "sessionId and message are required",
        code: "INVALID_PARAMS",
      });
      return;
    }

    const session = manager.getSession(sessionId);
    if (!session) {
      respond(false, undefined, {
        message: "Session not found or expired",
        code: "SESSION_NOT_FOUND",
      });
      return;
    }

    // Broadcast streaming events to subscribed clients
    const streamCallback: StreamCallback = (payload) => {
      context.broadcast(`guard.authoring.stream`, {
        sessionId,
        ...payload,
      });
    };

    try {
      const result = await manager.sendMessage(sessionId, message, streamCallback);
      respond(true, { text: result.text, error: result.error }, undefined);
    } catch (err) {
      respond(false, undefined, {
        message: `Authoring message failed: ${String(err)}`,
        code: "AUTHORING_MESSAGE_FAILED",
      });
    }
  });

  api.registerGatewayMethod("guard.authoring.cancel", async ({ params, respond }) => {
    const sessionId = typeof params.sessionId === "string" ? params.sessionId : "";

    if (!sessionId) {
      respond(false, undefined, {
        message: "sessionId is required",
        code: "INVALID_PARAMS",
      });
      return;
    }

    const ok = await manager.cancelSession(sessionId);
    respond(true, { ok, sessionId }, undefined);
  });
}

// ---------------------------------------------------------------------------
// SSE Hub -- pushes streaming events to connected dashboard clients
// ---------------------------------------------------------------------------

class SSEHub {
  private subscribers = new Map<string, Set<ServerResponse>>();

  subscribe(sessionId: string, res: ServerResponse) {
    let set = this.subscribers.get(sessionId);
    if (!set) {
      set = new Set();
      this.subscribers.set(sessionId, set);
    }
    set.add(res);
  }

  unsubscribe(sessionId: string, res: ServerResponse) {
    const set = this.subscribers.get(sessionId);
    if (set) {
      set.delete(res);
      if (set.size === 0) this.subscribers.delete(sessionId);
    }
  }

  push(sessionId: string, event: { type: string; data: unknown }) {
    const set = this.subscribers.get(sessionId);
    if (!set) return;
    const payload = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of set) {
      try {
        res.write(payload);
      } catch {
        set.delete(res);
      }
    }
  }

  removeAll(sessionId: string) {
    const set = this.subscribers.get(sessionId);
    if (set) {
      for (const res of set) {
        try {
          res.end();
        } catch {
          /* ignore */
        }
      }
      this.subscribers.delete(sessionId);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP Handler -- serves /guard/authoring/* routes on OpenClaw's HTTP server
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function jsonResponse(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function registerAuthoringHttpHandler(
  api: OpenClawPluginApi,
  manager: AuthoringSessionManager,
) {
  const sseHub = new SSEHub();

  api.registerHttpRoute({
    path: "/guard/authoring/",
    auth: "plugin",
    match: "prefix",
    handler: async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://localhost");

      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return true;
      }

      // GET /guard/authoring/events?sessionId=X -- SSE stream
      if (url.pathname === "/guard/authoring/events" && req.method === "GET") {
        const sessionId = url.searchParams.get("sessionId") ?? "";
        if (!sessionId || !manager.getSession(sessionId)) {
          jsonResponse(res, 404, { error: "Session not found" });
          return true;
        }
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        res.write(":ok\n\n");
        sseHub.subscribe(sessionId, res);
        req.on("close", () => sseHub.unsubscribe(sessionId, res));
        return true;
      }

      // POST /guard/authoring/start
      if (url.pathname === "/guard/authoring/start" && req.method === "POST") {
        try {
          const raw = await readBody(req);
          const body = raw ? JSON.parse(raw) : {};
          const mode =
            typeof body.mode === "string" && (body.mode === "create" || body.mode === "edit")
              ? body.mode
              : "create";
          const intentId = typeof body.intentId === "string" ? body.intentId : undefined;
          const result = await manager.startSession({ mode, intentId });
          jsonResponse(res, 200, result);
        } catch (err) {
          jsonResponse(res, 500, { error: String(err) });
        }
        return true;
      }

      // POST /guard/authoring/message
      if (url.pathname === "/guard/authoring/message" && req.method === "POST") {
        try {
          const raw = await readBody(req);
          const body = raw ? JSON.parse(raw) : {};
          const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
          const message = typeof body.message === "string" ? body.message : "";

          if (!sessionId || !message) {
            jsonResponse(res, 400, { error: "sessionId and message are required" });
            return true;
          }

          if (!manager.getSession(sessionId)) {
            jsonResponse(res, 404, { error: "Session not found or expired" });
            return true;
          }

          // Respond immediately, then process asynchronously via SSE
          jsonResponse(res, 200, { ok: true });

          const streamCallback: StreamCallback = (payload) => {
            sseHub.push(sessionId, payload);
          };

          manager.sendMessage(sessionId, message, streamCallback).catch((err) => {
            sseHub.push(sessionId, { type: "error", data: { error: String(err) } });
          });
        } catch (err) {
          jsonResponse(res, 500, { error: String(err) });
        }
        return true;
      }

      // POST /guard/authoring/cancel
      if (url.pathname === "/guard/authoring/cancel" && req.method === "POST") {
        try {
          const raw = await readBody(req);
          const body = raw ? JSON.parse(raw) : {};
          const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";

          if (!sessionId) {
            jsonResponse(res, 400, { error: "sessionId is required" });
            return true;
          }

          const ok = await manager.cancelSession(sessionId);
          sseHub.removeAll(sessionId);
          jsonResponse(res, 200, { ok, sessionId });
        } catch (err) {
          jsonResponse(res, 500, { error: String(err) });
        }
        return true;
      }

      jsonResponse(res, 404, { error: "Not found" });
      return true;
    },
  });
}
