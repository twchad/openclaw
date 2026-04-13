/**
 * Plugin tool allowlist token required for Guard scheme-authoring tools
 * (validate/compile/simulate/etc.). Embedded authoring passes this via
 * runEmbeddedPiAgent.pluginToolAllowlistExtras; the main agent must not include it.
 */
export const GUARD_AUTHORING_PLUGIN_ALLOWLIST_TOKEN = "group:guard-authoring";
