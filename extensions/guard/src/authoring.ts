import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import os from "node:os";
import path from "node:path";
import type { OpenClawPluginApi } from "../../../src/plugins/types.js";
import { fetchGuardApi, guardAuthErrorMessage } from "./auth.js";
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

export type GuardSignatureCaptureRun = {
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
  expiresAt: number;
};

const signatureCaptureRuns = new Map<string, GuardSignatureCaptureRun>();

function signatureCaptureKey(input: {
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
}): string | undefined {
  const agentId = input.agentId?.trim();
  const sessionId = input.sessionId?.trim();
  const sessionKey = input.sessionKey?.trim();
  const runId = input.runId?.trim();
  if (!agentId || !sessionId || !sessionKey || !runId) {
    return undefined;
  }
  return `${agentId}\u0000${sessionId}\u0000${sessionKey}\u0000${runId}`;
}

export function registerGuardSignatureCaptureRun(run: GuardSignatureCaptureRun): () => void {
  cleanupExpiredGuardSignatureCaptureRuns();
  const key = signatureCaptureKey(run);
  if (!key) {
    return () => {};
  }
  signatureCaptureRuns.set(key, run);
  return () => {
    signatureCaptureRuns.delete(key);
  };
}

export function lookupGuardSignatureCaptureRun(input: {
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
}): GuardSignatureCaptureRun | undefined {
  cleanupExpiredGuardSignatureCaptureRuns();
  const key = signatureCaptureKey(input);
  if (!key) {
    return undefined;
  }
  const run = signatureCaptureRuns.get(key);
  if (!run) {
    return undefined;
  }
  if (run.expiresAt <= Date.now()) {
    signatureCaptureRuns.delete(key);
    return undefined;
  }
  return run;
}

export function isGuardAuthoringRunIdentity(input: {
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
}): boolean {
  return (
    input.sessionId?.startsWith("guard-authoring-") === true ||
    input.sessionKey?.includes(":guard-authoring-") === true ||
    input.runId?.startsWith("guard-authoring-") === true
  );
}

export function cleanupExpiredGuardSignatureCaptureRuns(now = Date.now()) {
  for (const [key, run] of signatureCaptureRuns) {
    if (run.expiresAt <= now) {
      signatureCaptureRuns.delete(key);
    }
  }
}

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
    const workspaceDir = api.config?.agents?.defaults?.workspace ?? process.cwd();
    const schemaInventoryOptions = [
      {
        workspaceDir,
        config: api.config,
      },
      {
        workspaceDir,
        config: api.config,
        modelProvider: "openai",
        modelId: "gpt-5.4",
        toolConstructionPlan: {
          includeBaseCodingTools: true,
          includeShellTools: true,
          includeChannelTools: false,
          includeOpenClawTools: true,
          includePluginTools: false,
        },
      },
    ];
    for (const options of schemaInventoryOptions) {
      try {
        const tools = createOpenClawCodingTools(options);
        for (const tool of tools) {
          if (tool.parameters && !coreToolSchemas.has(tool.name)) {
            coreToolSchemas.set(tool.name, tool.parameters);
          }
        }
      } catch {
        // Keep trying other inventory passes.
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
      if (tool.id.startsWith("guard_")) {
        continue;
      }
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
    if (!entries || entries.length === 0) {
      continue;
    }
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
  if (!params || typeof params !== "object") {
    return "{}";
  }
  const schema = params as Record<string, unknown>;
  const props = schema.properties as Record<string, unknown> | undefined;
  if (!props) {
    return "{}";
  }
  const keys = Object.keys(props).slice(0, 8);
  const summary = keys
    .map((k) => {
      const prop = props[k] as Record<string, unknown> | undefined;
      const rawType = prop?.type;
      const type = typeof rawType === "string" ? rawType : "unknown";
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
  mode: AuthoringMode;
  intentId?: string;
  graphId?: string;
  scheme?: unknown;
  toolCatalog: string;
  fpContext?: AuthoringFPContext;
  fnContext?: AuthoringFNContext;
};

type AuthoringMode = "create" | "edit" | "fp_review" | "fn_review";

type AuthoringFPContext = {
  decisionId: string;
  observation: string;
  schemeId: string;
  violations: AuthoringFPViolation[];
  ruleId?: string;
  score?: number;
  ruleType?: string;
  violation?: string;
};

type AuthoringFPViolation = {
  violationId?: string;
  ruleId: string;
  ruleType: string;
  violation: string;
  score: number;
  expectedAction?: string;
  missingSteps?: string[];
  matchedPattern?: string;
  contentType?: string;
};

type AuthoringFNContext = {
  decisionId: string;
  observation: string;
  ruleId: string;
  schemeId: string;
  score: number;
  threshold: number;
  zScore: number;
  ruleType: string;
};

type AuthoringIntrospectionContext = "generic" | "new_scheme" | "edit_existing";

export function buildAuthoringSystemPrompt(params: AuthoringPromptParams): string {
  const parts: string[] = [];

  parts.push(`# Guard Scheme Authoring Agent

You are an expert AI agent specializing in authoring Guard authorization schemes for other AI agents. Your task is to convert a user's security intent into a formally structured Guard scheme configuration. You have expert statistical reasoning as well, which helps you build semantic authorization schemes that work in a balanced way.

## Your Tools

You can call guard_* tools normally. You may also call non-guard tools from the guarded-agent catalog ONLY as signature probes: during authoring, OpenClaw captures their Guard-visible tool-call shape and does not execute them. Use these probes before writing SEQUENCE requiredInput, requiredOutput, or bindings against uncertain tool arguments.

If a non-guard tool such as apply_patch appears in the tool catalog, call that tool with harmless-shaped arguments to capture its signature. You may call it directly when it is visible, or use tool_search/tool_describe/tool_call when the runtime catalogs it behind Tool Search. Do not infer binding paths from catalog summaries alone.

When a non-guard tool probe returns a guard_signature_capture payload, use bindableArgPaths exactly as reported. Do not infer binding paths from tool descriptions, from the visible call method, or from guard_simulate. guard_simulate evaluates caller-supplied GuardDecisionRequest events; it does not discover real OpenClaw tool signatures. If the value you need is not bindable, choose another observed field or create a Guard helper whose attested input/output exposes it.

IMPORTANT: The "Guard Tool Signatures" section below contains the exact JSON parameter schemas for guard_* tools. Follow those schemas exactly when calling tools.

Your available tools:
- \`guard_introspect\`: Get the full rule type specification. Call this first if you need to understand rule types, required fields, or composition patterns.
- \`guard_graph_list\`: List all existing knowledge graphs. Returns graphId, intentId, intentText for each. Use this to discover available intents when no specific ID is known.
- \`guard_graph_read\`: Read an existing knowledge graph by graphId. Use this to understand the intent structure before drafting rules.
- \`guard_graph_save\`: Save a knowledge graph that maps user intent to risk surfaces. Nodes must include stable nodeId values so edges can reference source/target correctly.
- \`guard_scheme_read\`: Read a scheme permitted by the current authoring session. In New Scheme mode, this is limited to the scheme created by this session. Use this to review existing rules before editing.
- \`guard_validate_rule\`: Validate a single rule before adding it to a scheme. Prefer passing rule fields directly at top level (ruleId, ruleType, title, scope, enabled, and the typed config). Fix all errors before proceeding.
- \`guard_validate_scheme\`: Validate a complete scheme. Pass { rules: [...] }; draft scheme-level gate fields may be included but lint is driven by the rules array.
- \`guard_simulate\`: Test draft rules against sample events to verify detection accuracy. Test both events that should be blocked AND events that should pass.
- \`guard_compile_scheme\`: Compile and activate a validated scheme. Only call after validation and simulation pass.
- \`guard_scheme_update\`: Apply targeted changes to a scheme permitted by the current authoring session. In New Scheme mode, this is limited to the scheme created by this session.
- \`guard_helper_create\`: Create or update a Guard-managed helper. Each helper is a directory on disk that persists state between runs. Can provide script directly, or set stub:true for complex helpers the user will implement.
- \`guard_helper_test\`: Test a helper with sample inputs before compiling the scheme. Runs without attestation.
- \`guard_helper_list\`: List all existing Guard-managed helpers. Use to discover helpers when editing an existing scheme.
- \`guard_helper_read\`: Read a single helper by ID. Returns script loaded from disk, file listing, input schema, and permissions.
- \`guard_helper_write_file\`: Write a file into a helper's directory (supporting modules, dependency manifests, data files).
- \`guard_helper_install_deps\`: Install dependencies for a helper (npm install / pip install).
- \`guard_elaboration_analyze\`: Analyze candidate semantic elaborations for cluster health before validation.
- \`guard_query_benign_corpus\`: Inspect core/held-out benign examples and current per-rule benign corpus additions.
- \`guard_scheme_expand\`: Apply addition-only updates to a scheme permitted by the current authoring session.

Optional control tool:
- \`guard_author_confirm\`: Show a structured confirmation card for a real user decision. This is optional; if a normal prose question is clearer, ask it and end the turn.

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
10. **Compile** with \`guard_compile_scheme\` when validation and simulation pass. Use OBSERVE by default. Do not ask for another confirmation unless there is a meaningful unresolved decision.

## Important Guidelines

- Use guard_* tools for real authoring actions. Non-guard catalog tools are available only as signature probes; calling one captures a guard_signature_capture payload and does not execute the underlying action.
- Always validate before compiling. Never skip validation.
- For \`guard_validate_rule\`, pass the rule fields directly at top level. Do not stop if validation fails; read the lint result, fix the rule, and retry.
- For \`guard_validate_scheme\`, pass a \`rules\` array. Do not treat draft gate fields as validation blockers; compile/update performs gate validation.
- Use simulation to test for false positives on safe operations.
- Confirm with the user only when a decision is genuinely needed: unresolved intent ambiguity, ENFORCE promotion, broad exceptions/sinks, high-risk helper permissions, or when the user explicitly asks for confirmation.
- When writing elaboration text for SEMANTICS rules, be specific and grounded. Avoid vague language.
- When writing denyPattern for SYNTAX rules, test patterns against realistic tool arguments.
- For SEQUENCE rules, verify the required tool order makes sense for the user's workflow.

## Execution Style (Critical)

- Be execution-first, not confirmation-first. Act like a senior engineer pair-programming, not a chatbot.
- If the user request is actionable, call guard_* tools in the SAME turn. NEVER stop at "I can do that" or "ready when you are."
- Keep narration to one brief sentence per step. Lead with tool calls, follow with a short status line.
- Ask questions only when required information is genuinely missing from the conversation.
- Never claim you cannot execute guard_* tools. You CAN. Attempt the calls; if one fails, report the exact error.
- When the user says "yes", "ok", "approved", "do it", "go ahead" — that IS confirmation. Execute immediately.
- If the user says "no confirmations" or "don't ask", skip optional confirmation prompts. Still pause for genuinely ambiguous or high-risk decisions.
`);

  const isEditLike =
    params.mode === "edit" || params.mode === "fp_review" || params.mode === "fn_review";

  if (isEditLike) {
    const editContext: string[] = [
      `## Edit Existing Scheme Mode

You are editing or repairing an existing Guard intent/graph. Do NOT treat this as a new unrelated scheme. Preserve rules the user hasn't asked to modify. If no active scheme is loaded below, that means the intent/graph exists but the rules are missing or broken; create the missing initial scheme for this existing intent/graph instead of asking the user for IDs.`,
    ];

    if (params.intentId || params.graphId) {
      editContext.push("");
      editContext.push(
        "**IMPORTANT — These IDs are already resolved for this session. Use them directly in tool calls (guard_graph_read, guard_compile_scheme, etc.). Do NOT ask the user for IDs.**",
      );
      if (params.intentId) {
        editContext.push(`- intentId: \`${params.intentId}\``);
      }
      if (params.graphId) {
        editContext.push(`- graphId: \`${params.graphId}\``);
      }
      editContext.push("");
    }

    if (params.scheme) {
      editContext.push(`### Current Active Scheme

\`\`\`json
${JSON.stringify(params.scheme, null, 2)}
\`\`\``);
    } else {
      editContext.push(`### Current Active Scheme

No active scheme was returned for this edit session. Continue in repair mode:
- If intentId or graphId is provided above, use it directly.
- If graphId is provided, call guard_graph_read with that graphId.
- If only intentId is provided, call guard_graph_list if needed to resolve graphId, then guard_graph_read.
- Draft rules for this existing intent/graph, validate, simulate, and compile in OBSERVE mode.
- Do not ask the user which scheme to edit unless neither intentId nor graphId is available and guard_graph_list cannot identify the target.`);
    }

    parts.push(editContext.join("\n"));
  } else if (params.mode === "create") {
    parts.push(`## New Scheme (Create Mode)

You are creating a new Guard scheme from scratch for a new user intent. You HAVE full access to all guard_* tools and MUST use them. They are available as callable tools in this session — call them directly.

Follow the full workflow: understand intent → call \`guard_introspect\` → build knowledge graph → draft rules → validate → simulate → compile.

Start by calling \`guard_introspect\` to get the current rule specification, then proceed with tool calls immediately. Do NOT output a JSON payload for the user to "paste" — that is never acceptable. YOU call the tools.

If the user asks to work with an existing intent, graph, or broken scheme, that should be an Edit Existing session, not New Scheme. In New Scheme mode, only ask for an existing graph/intent if the user's request explicitly references one.

In New Scheme mode, do NOT inspect or mutate ambient existing schemes. After you compile a scheme in this session, you may use guard_scheme_read, guard_scheme_update, and guard_scheme_expand only against that session-created scheme.
	`);
  }

  if (params.mode === "fp_review" && params.fpContext) {
    parts.push(`## False Positive Review Context

The user marked a prior Guard decision as a false positive. Load the current scheme and inspect the target rule before changing it. Prefer the smallest fix that preserves true-positive coverage: add a rule-specific benignCorpus entry, adjust a threshold, add a narrow exception, or disagree if the decision was correctly blocked.

\`\`\`json
${JSON.stringify(params.fpContext, null, 2)}
\`\`\``);
  }

  if (params.mode === "fn_review" && params.fnContext) {
    parts.push(`## False Negative Review Context

The user marked a prior Guard decision as a false negative. Load the current scheme and inspect the target rule before changing it. Prefer targeted recall fixes: add realistic elaborations, add or tighten a SYNTAX companion, split a broad semantic rule, or adjust threshold only after simulation.

\`\`\`json
${JSON.stringify(params.fnContext, null, 2)}
\`\`\``);
  }

  parts.push(params.toolCatalog);
  parts.push("");

  parts.push(`## Guard Rule Type Specification

Do NOT rely on memorized rule schemas. Call \`guard_introspect\` at the start of any authoring session to get the exact, current rule type specification including required fields, composition patterns, and anti-patterns. The introspection spec is authoritative — always defer to it over any prior knowledge. When simulating knowledge-test schemes, verify the violation produces pendingKnowledgeTest; do not answer the knowledge test during simulation.
`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Phase 3: Authoring Session Manager
// ---------------------------------------------------------------------------

type AuthoringSession = {
  sessionId: string;
  mode: AuthoringMode;
  intentId?: string;
  graphId?: string;
  tempDir: string;
  sessionFile: string;
  toolCatalog: string;
  currentScheme?: unknown;
  fpContext?: AuthoringFPContext;
  fnContext?: AuthoringFNContext;
  createdAt: number;
  lastActiveAt: number;
  /** Resolved guard_* tool names for this session, used as the run's toolsAllow. */
  guardToolNames: string[];
  /** Non-guard tool names visible only for authoring signature capture. */
  guardedToolNames: string[];
  /** Non-guard guarded-agent catalog entries shown in the prompt inventory. */
  guardedToolEntries: ToolCatalogEntry[];
  /** Schemes created by this create-mode session and therefore safe to inspect/update. */
  ownedSchemeIds: Set<string>;
  /** Intents created by this create-mode session and therefore safe to inspect/update. */
  ownedIntentIds: Set<string>;
  activeStream?: StreamCallback;
  pendingConfirmations: Map<string, PendingAuthoringConfirmation>;
};

type StreamCallback = (payload: {
  type: "text" | "tool_call" | "tool_result" | "done" | "error" | "confirmation_required";
  data: unknown;
}) => void;

type PendingAuthoringConfirmation = {
  confirmationId: string;
  resolve: (answer: string) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

type AuthorConfirmParams = {
  question?: unknown;
  options?: unknown;
  context?: unknown;
};

const AUTHORING_SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const AUTHORING_TIMEOUT_MS = 360_000; // Long enough for one confirmation wait.
const AUTHORING_CONFIRM_TIMEOUT_MS = 5 * 60 * 1000;
const AUTHORING_SESSIONS_KEY = Symbol.for("openclaw.guard.authoring.sessions");

const globalAuthoringState = globalThis as typeof globalThis & {
  [AUTHORING_SESSIONS_KEY]?: Map<string, AuthoringSession>;
};

function getGlobalAuthoringSessions(): Map<string, AuthoringSession> {
  return (
    globalAuthoringState[AUTHORING_SESSIONS_KEY] ??
    (globalAuthoringState[AUTHORING_SESSIONS_KEY] = new Map<string, AuthoringSession>())
  );
}

export class AuthoringSessionManager {
  private sessions = getGlobalAuthoringSessions();
  private ownedSessionIds = new Set<string>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private api: OpenClawPluginApi;
  private guardEndpoint: string;
  private credentialFile: string | undefined;
  private runAgent: RunEmbeddedPiAgentFn | null = null;
  private resolvedAgentId = "main";

  constructor(api: OpenClawPluginApi, guardEndpoint: string, credentialFile?: string) {
    this.api = api;
    this.guardEndpoint = guardEndpoint;
    this.credentialFile = credentialFile;
    void this.resolveAgentId();
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

  private async resolveAuthoringGuardToolNames(): Promise<string[]> {
    const { resolvePluginTools, resetPluginToolDescriptorCache } =
      await import("../../../src/plugins/tools.js");
    resetPluginToolDescriptorCache();
    return resolvePluginTools({
      context: {
        config: this.api.config,
        workspaceDir: this.api.config?.agents?.defaults?.workspace ?? process.cwd(),
      },
      existingToolNames: new Set<string>(),
      toolAllowlist: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
      suppressNameConflicts: true,
    })
      .filter((t) => t.name.startsWith("guard_"))
      .map((t) => t.name);
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
  ): Promise<unknown> {
    try {
      const resp = await fetchGuardApi(
        this.api,
        { endpoint: this.guardEndpoint, timeoutMs: 10_000, credentialFile: this.credentialFile },
        path,
        {
          method,
          headers: {
            ...(body ? { "Content-Type": "application/json" } : {}),
            ...headers,
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!resp.ok) {
        if (resp.status === 401) {
          return { error: guardAuthErrorMessage(this.credentialFile) };
        }
        return null;
      }
      return await resp.json();
    } catch {
      return null;
    }
  }

  async startSession(params: {
    mode: AuthoringMode;
    intentId?: string;
    graphId?: string;
    fpContext?: AuthoringFPContext;
    fnContext?: AuthoringFNContext;
  }): Promise<{ sessionId: string; mode: string; currentScheme?: unknown }> {
    const sessionId = `guard-authoring-${randomUUID()}`;
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "guard-authoring-"));
    const sessionFile = path.join(tempDir, "session.json");

    // Resolve tool catalog (guarded agent's tools — NOT guard_* tools, which are function-calling tools)
    const { entries: toolCatalogEntries, formatted: toolCatalog } =
      await resolveAuthoringToolCatalog(this.api);
    const guardedToolNames = Array.from(new Set(toolCatalogEntries.map((entry) => entry.name)));

    // Resolve guard_* tool names so we can pin the run's `toolsAllow` to them
    // (the model never sees coding/exec/etc. tools).
    const { resolvePluginTools, resetPluginToolDescriptorCache } =
      await import("../../../src/plugins/tools.js");
    resetPluginToolDescriptorCache();
    const guardToolNames = resolvePluginTools({
      context: {
        config: this.api.config,
        workspaceDir: this.api.config?.agents?.defaults?.workspace ?? process.cwd(),
      },
      existingToolNames: new Set<string>(),
      toolAllowlist: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
      suppressNameConflicts: true,
    })
      .filter((t) => t.name.startsWith("guard_"))
      .map((t) => t.name);
    if (guardToolNames.length === 0) {
      throw new Error(
        "guard-authoring: no guard_* tools resolved. The Guard plugin appears to be unloaded or its tool registration failed.",
      );
    }

    // Fetch current scheme and resolve graphId if editing
    let currentScheme: unknown;
    let graphId: string | undefined = params.graphId;
    if (params.mode === "edit" || params.mode === "fp_review" || params.mode === "fn_review") {
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
      if (resolveIntentId && !graphId) {
        const graphs = (await this.guardFetch("/v1/graphs", "GET")) as Array<{
          graphId?: string;
          intentId?: string;
        }> | null;
        if (graphs) {
          const match = graphs.find((g) => g.intentId === resolveIntentId);
          if (match?.graphId) {
            graphId = match.graphId;
          }
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
      fpContext: params.fpContext,
      fnContext: params.fnContext,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      guardToolNames,
      guardedToolNames,
      guardedToolEntries: toolCatalogEntries,
      ownedSchemeIds: new Set(),
      ownedIntentIds: new Set(),
      pendingConfirmations: new Map(),
    };

    this.sessions.set(sessionId, session);
    this.ownedSessionIds.add(sessionId);

    this.api.logger.info(
      `[guard-authoring] session=${sessionId} mode=${params.mode} guard_tools_available=${guardToolNames.length} tools=[${guardToolNames.join(",")}]`,
    );

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

    const guardToolNames = await this.resolveAuthoringGuardToolNames();
    if (guardToolNames.length > 0) {
      session.guardToolNames = guardToolNames;
    }
    if (session.guardToolNames.length === 0) {
      return {
        text: "",
        error:
          "guard-authoring: no guard_* tools resolved for this run. Restart the gateway after rebuilding OpenClaw.",
      };
    }

    const runAgent = await this.ensureAgent();

    const systemPrompt = buildAuthoringSystemPrompt({
      mode: session.mode,
      intentId: session.intentId,
      graphId: session.graphId,
      scheme: session.currentScheme,
      toolCatalog: session.toolCatalog,
      fpContext: session.fpContext,
      fnContext: session.fnContext,
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
    }> => {
      let lastEmittedLength = 0;
      const runId = `guard-authoring-${Date.now()}`;
      const sessionKey = `agent:${this.resolvedAgentId}:${session.sessionId}`;
      const unregisterCapture = registerGuardSignatureCaptureRun({
        agentId: this.resolvedAgentId,
        sessionId: session.sessionId,
        sessionKey,
        runId,
        expiresAt: Date.now() + AUTHORING_TIMEOUT_MS + 60_000,
      });

      try {
        const result = (await runAgent({
          sessionId: session.sessionId,
          sessionKey,
          sandboxSessionKey: sessionKey,
          sessionFile: session.sessionFile,
          workspaceDir: this.api.config?.agents?.defaults?.workspace ?? process.cwd(),
          config: this.api.config,
          prompt,
          extraSystemPrompt: systemPrompt,
          timeoutMs: AUTHORING_TIMEOUT_MS,
          runId,
          provider,
          model,
          disableTools: false,
          // `group:plugins` covers runtime guard_* tools (gated by the standard
          // plugin group); the authoring token covers scheme-authoring tools. Both
          // are needed because some user configs don't surface `group:plugins`
          // through the global allowlist.
          pluginToolAllowlistExtras: ["group:plugins", GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN],
          // guard_* tools execute normally. Non-guard catalog tools are also
          // materialized so direct calls and Tool Search can reach the
          // before_tool_call capture boundary; authoring runs fail closed before
          // executing any non-guard tool.
          toolsAllow: Array.from(new Set([...session.guardToolNames, ...session.guardedToolNames])),
          // Skip the user-facing tool policy pipeline (tools.profile / tools.allow /
          // agent.tools.allow). A profile like "coding" — whose allow list contains
          // only core tool ids — would otherwise strip every guard_* plugin tool
          // before toolsAllow runs, leaving the model with zero tools.
          bypassAgentToolPolicy: true,
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
            if (evt.stream !== "tool") {
              return;
            }
            const phase = evt.data.phase as string;
            const toolName = (evt.data.name as string) ?? "unknown";
            if (phase === "start") {
              if (toolName !== "guard_author_confirm") {
                onStream?.({
                  type: "tool_call",
                  data: { tool: toolName, args: evt.data.args ?? {} },
                });
              }
            } else if (phase === "result") {
              const isError = evt.data.isError === true;
              if (toolName !== "guard_author_confirm") {
                onStream?.({
                  type: "tool_result",
                  data: {
                    tool: toolName,
                    result: evt.data.meta ?? {},
                    isError,
                  },
                });
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

        return {
          finalText,
        };
      } finally {
        unregisterCapture();
      }
    };

    try {
      session.activeStream = onStream;

      const turn = await runSingleTurn(message);
      const finalText = turn.finalText;
      onStream?.({ type: "done", data: { text: finalText } });
      return { text: finalText };
    } catch (err) {
      const errorMsg = `Authoring agent error: ${String(err)}`;
      onStream?.({ type: "error", data: { error: errorMsg } });
      return { text: "", error: errorMsg };
    } finally {
      session.activeStream = undefined;
    }
  }

  async requestConfirmation(
    sessionKey: string | undefined,
    params: AuthorConfirmParams,
  ): Promise<{ answer: string }> {
    const session = this.findSessionBySessionKey(sessionKey);
    if (!session) {
      throw new Error("No active Guard authoring session found for confirmation.");
    }
    const question = typeof params.question === "string" ? params.question.trim() : "";
    if (!question) {
      throw new Error("guard_author_confirm requires a non-empty question.");
    }
    const options = Array.isArray(params.options)
      ? params.options
          .filter((x): x is string => typeof x === "string" && x.trim().length > 0)
          .map((x) => x.trim())
      : undefined;
    const context = typeof params.context === "string" ? params.context : undefined;

    const answer = await this.waitForSessionConfirmation(session, { question, options, context });
    return { answer };
  }

  private async waitForSessionConfirmation(
    session: AuthoringSession,
    params: { question: string; options?: string[]; context?: string },
  ): Promise<string> {
    const question = params.question.trim();
    const confirmationId = randomUUID();

    return await new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        session.pendingConfirmations.delete(confirmationId);
        reject(new Error("Confirmation timed out."));
      }, AUTHORING_CONFIRM_TIMEOUT_MS);
      if (timeout.unref) {
        timeout.unref();
      }
      session.pendingConfirmations.set(confirmationId, {
        confirmationId,
        resolve,
        reject,
        timeout,
      });
      session.activeStream?.({
        type: "confirmation_required",
        data: {
          confirmationId,
          question,
          ...(params.options && params.options.length > 0 ? { options: params.options } : {}),
          ...(params.context ? { context: params.context } : {}),
        },
      });
    });
  }

  confirm(sessionId: string, confirmationId: string, answer: string): boolean {
    const session = this.sessions.get(sessionId);
    const pending = session?.pendingConfirmations.get(confirmationId);
    if (!session || !pending) {
      return false;
    }
    clearTimeout(pending.timeout);
    session.pendingConfirmations.delete(confirmationId);
    pending.resolve(answer);
    return true;
  }

  async cancelSession(sessionId: string): Promise<boolean> {
    return this.destroySession(sessionId);
  }

  private async destroySession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    this.sessions.delete(sessionId);
    this.ownedSessionIds.delete(sessionId);
    for (const pending of session.pendingConfirmations.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error("Authoring session cancelled."));
    }
    session.pendingConfirmations.clear();
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

  introspectionContextForSessionKey(
    sessionKey: string | undefined,
    explicitContext?: unknown,
    sessionId?: string,
    options?: { allowSoleSessionFallback?: boolean },
  ): AuthoringIntrospectionContext {
    if (typeof explicitContext === "string" && explicitContext.trim()) {
      return explicitContext.trim() as AuthoringIntrospectionContext;
    }
    const session = this.findSessionBySessionKey(sessionKey, {
      allowSoleSessionFallback: options?.allowSoleSessionFallback ?? false,
      sessionId,
    });
    if (!session) {
      return "generic";
    }
    return session.mode === "create" ? "new_scheme" : "edit_existing";
  }

  ensurePermittedSchemeTarget(
    sessionKey: string | undefined,
    target: { schemeId?: unknown; intentId?: unknown },
    operation: string,
    sessionId?: string,
    options?: { allowSoleSessionFallback?: boolean; requireSession?: boolean },
  ): { ok: boolean; error?: string } {
    const session = this.findSessionBySessionKey(sessionKey, {
      allowSoleSessionFallback: options?.allowSoleSessionFallback ?? false,
      sessionId,
    });
    if (!session) {
      if (options?.requireSession) {
        return {
          ok: false,
          error: `No active Guard authoring session found for ${operation}. Restart the authoring session and try again.`,
        };
      }
      return { ok: true };
    }
    if (session.mode !== "create") {
      return { ok: true };
    }
    const schemeId = typeof target.schemeId === "string" ? target.schemeId.trim() : "";
    const intentId = typeof target.intentId === "string" ? target.intentId.trim() : "";
    if (!schemeId && !intentId) {
      return {
        ok: false,
        error: `New Scheme sessions cannot ${operation} ambient existing schemes. Compile a scheme in this session first, or start Edit Existing.`,
      };
    }
    if (
      (schemeId && session.ownedSchemeIds.has(schemeId)) ||
      (intentId && session.ownedIntentIds.has(intentId))
    ) {
      return { ok: true };
    }
    return {
      ok: false,
      error: `New Scheme sessions cannot ${operation} pre-existing schemes. Target only the scheme created by this session, or start Edit Existing.`,
    };
  }

  recordOwnedSchemeForSessionKey(
    sessionKey: string | undefined,
    target: { schemeId?: unknown; intentId?: unknown },
    sessionId?: string,
    options?: { allowSoleSessionFallback?: boolean },
  ) {
    const session = this.findSessionBySessionKey(sessionKey, {
      allowSoleSessionFallback: options?.allowSoleSessionFallback ?? false,
      sessionId,
    });
    if (!session || session.mode !== "create") {
      return;
    }
    const schemeId = typeof target.schemeId === "string" ? target.schemeId.trim() : "";
    const intentId = typeof target.intentId === "string" ? target.intentId.trim() : "";
    if (schemeId) {
      session.ownedSchemeIds.add(schemeId);
    }
    if (intentId) {
      session.ownedIntentIds.add(intentId);
    }
  }

  private findSessionBySessionKey(
    sessionKey: string | undefined,
    options?: { allowSoleSessionFallback?: boolean; sessionId?: string },
  ): AuthoringSession | undefined {
    const sessionId = typeof options?.sessionId === "string" ? options.sessionId.trim() : "";
    if (sessionId) {
      const direct = this.sessions.get(sessionId);
      if (direct) {
        return direct;
      }
    }
    const key = typeof sessionKey === "string" ? sessionKey : "";
    for (const session of this.sessions.values()) {
      if (key.includes(session.sessionId)) {
        return session;
      }
    }
    if (options?.allowSoleSessionFallback !== false && this.sessions.size === 1) {
      return this.sessions.values().next().value;
    }
    return undefined;
  }

  dispose() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const id of this.ownedSessionIds) {
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
      typeof params.mode === "string" && isAuthoringMode(params.mode) ? params.mode : "create";
    const intentId = typeof params.intentId === "string" ? params.intentId : undefined;
    const graphId = typeof params.graphId === "string" ? params.graphId : undefined;
    const fpContext = normalizeFPContext(params.fpContext);
    const fnContext = normalizeFNContext(params.fnContext);

    try {
      const result = await manager.startSession({ mode, intentId, graphId, fpContext, fnContext });
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

  api.registerGatewayMethod("guard.authoring.confirm", async ({ params, respond }) => {
    const sessionId = typeof params.sessionId === "string" ? params.sessionId : "";
    const confirmationId = typeof params.confirmationId === "string" ? params.confirmationId : "";
    const answer = typeof params.answer === "string" ? params.answer : "";
    if (!sessionId || !confirmationId || !answer) {
      respond(false, undefined, {
        message: "sessionId, confirmationId, and answer are required",
        code: "INVALID_PARAMS",
      });
      return;
    }
    const ok = manager.confirm(sessionId, confirmationId, answer);
    respond(true, { ok, sessionId, confirmationId }, undefined);
  });
}

function isAuthoringMode(mode: string): mode is AuthoringMode {
  return mode === "create" || mode === "edit" || mode === "fp_review" || mode === "fn_review";
}

function normalizeFPContext(value: unknown): AuthoringFPContext | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const raw = value as Record<string, unknown>;
  if (
    typeof raw.decisionId !== "string" ||
    typeof raw.observation !== "string" ||
    typeof raw.schemeId !== "string"
  ) {
    return undefined;
  }
  const violations = Array.isArray(raw.violations)
    ? raw.violations.flatMap((item) => {
        if (!item || typeof item !== "object") {
          return [];
        }
        const v = item as Record<string, unknown>;
        if (
          typeof v.ruleId !== "string" ||
          typeof v.ruleType !== "string" ||
          typeof v.violation !== "string"
        ) {
          return [];
        }
        return [
          {
            violationId: typeof v.violationId === "string" ? v.violationId : undefined,
            ruleId: v.ruleId,
            ruleType: v.ruleType,
            violation: v.violation,
            score: typeof v.score === "number" ? v.score : 0,
            expectedAction: typeof v.expectedAction === "string" ? v.expectedAction : undefined,
            missingSteps: Array.isArray(v.missingSteps)
              ? v.missingSteps.filter((step): step is string => typeof step === "string")
              : undefined,
            matchedPattern: typeof v.matchedPattern === "string" ? v.matchedPattern : undefined,
            contentType: typeof v.contentType === "string" ? v.contentType : undefined,
          },
        ];
      })
    : [];
  const legacyViolation =
    typeof raw.ruleId === "string" &&
    typeof raw.ruleType === "string" &&
    typeof raw.violation === "string"
      ? {
          ruleId: raw.ruleId,
          ruleType: raw.ruleType,
          violation: raw.violation,
          score: typeof raw.score === "number" ? raw.score : 0,
        }
      : undefined;
  const normalizedViolations =
    violations.length > 0 ? violations : legacyViolation ? [legacyViolation] : [];
  if (normalizedViolations.length === 0) {
    return undefined;
  }
  const first = normalizedViolations[0];
  return {
    decisionId: raw.decisionId,
    observation: raw.observation,
    schemeId: raw.schemeId,
    violations: normalizedViolations,
    ruleId: typeof raw.ruleId === "string" ? raw.ruleId : first.ruleId,
    score: typeof raw.score === "number" ? raw.score : first.score,
    ruleType: typeof raw.ruleType === "string" ? raw.ruleType : first.ruleType,
    violation: typeof raw.violation === "string" ? raw.violation : first.violation,
  };
}

function normalizeFNContext(value: unknown): AuthoringFNContext | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const raw = value as Record<string, unknown>;
  if (
    typeof raw.decisionId !== "string" ||
    typeof raw.observation !== "string" ||
    typeof raw.ruleId !== "string" ||
    typeof raw.schemeId !== "string"
  ) {
    return undefined;
  }
  return {
    decisionId: raw.decisionId,
    observation: raw.observation,
    ruleId: raw.ruleId,
    schemeId: raw.schemeId,
    score: typeof raw.score === "number" ? raw.score : 0,
    threshold: typeof raw.threshold === "number" ? raw.threshold : 0,
    zScore: typeof raw.zScore === "number" ? raw.zScore : 0,
    ruleType: typeof raw.ruleType === "string" ? raw.ruleType : "",
  };
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
      if (set.size === 0) {
        this.subscribers.delete(sessionId);
      }
    }
  }

  push(sessionId: string, event: { type: string; data: unknown }) {
    const set = this.subscribers.get(sessionId);
    if (!set) {
      return;
    }
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
            typeof body.mode === "string" && isAuthoringMode(body.mode) ? body.mode : "create";
          const intentId = typeof body.intentId === "string" ? body.intentId : undefined;
          const graphId = typeof body.graphId === "string" ? body.graphId : undefined;
          const result = await manager.startSession({
            mode,
            intentId,
            graphId,
            fpContext: normalizeFPContext(body.fpContext),
            fnContext: normalizeFNContext(body.fnContext),
          });
          jsonResponse(res, 200, result);
        } catch (err) {
          jsonResponse(res, 500, { error: String(err) });
        }
        return true;
      }

      // POST /guard/authoring/confirm
      if (url.pathname === "/guard/authoring/confirm" && req.method === "POST") {
        try {
          const raw = await readBody(req);
          const body = raw ? JSON.parse(raw) : {};
          const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
          const confirmationId = typeof body.confirmationId === "string" ? body.confirmationId : "";
          const answer = typeof body.answer === "string" ? body.answer : "";

          if (!sessionId || !confirmationId || !answer) {
            jsonResponse(res, 400, {
              error: "sessionId, confirmationId, and answer are required",
            });
            return true;
          }

          const ok = manager.confirm(sessionId, confirmationId, answer);
          jsonResponse(res, ok ? 200 : 404, { ok, sessionId, confirmationId });
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
