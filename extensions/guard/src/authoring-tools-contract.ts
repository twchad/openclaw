import { GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN } from "./authoring-allowlist-token.js";

/**
 * Tool surface contract for the Guard OpenClaw plugin.
 *
 * Regression history: authoring tools were repeatedly dropped when the plugin
 * descriptor cache was warmed by a `group:plugins`-only resolve. Keep these
 * lists in sync with registerRuntimeTools / registerAuthoringTools in index.ts.
 */

/** Visible to the guarded agent with `group:plugins` only (no authoring token). */
export const GUARD_RUNTIME_TOOL_NAMES = [
  "guard_helper_run",
  "guard_graph_read",
  "guard_graph_list",
  "guard_knowledge_test",
  "guard_hold_release",
  "guard_hold_status",
] as const;

/** Scheme authoring tools — require {@link GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN}. */
export const GUARD_AUTHORING_ONLY_TOOL_NAMES = [
  "guard_author_confirm",
  "guard_introspect",
  "guard_validate_rule",
  "guard_validate_scheme",
  "guard_compile_scheme",
  "guard_scheme_update",
  "guard_simulate",
  "guard_elaboration_analyze",
  "guard_query_benign_corpus",
  "guard_scheme_expand",
  "guard_graph_save",
  "guard_helper_create",
  "guard_helper_test",
  "guard_helper_list",
  "guard_helper_read",
  "guard_helper_write_file",
  "guard_helper_install_deps",
  "guard_scheme_read",
] as const;

export const GUARD_ALL_PLUGIN_TOOL_NAMES = [
  ...GUARD_RUNTIME_TOOL_NAMES,
  ...GUARD_AUTHORING_ONLY_TOOL_NAMES,
] as const;

/** Allowlist passed by AuthoringSessionManager when resolving guard_* tools. */
export const GUARD_AUTHORING_RESOLVE_ALLOWLIST = [
  "group:plugins",
  GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN,
] as const;

export const MIN_GUARD_AUTHORING_SESSION_TOOL_COUNT = GUARD_ALL_PLUGIN_TOOL_NAMES.length;
