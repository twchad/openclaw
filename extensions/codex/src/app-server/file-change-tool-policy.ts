import type { JsonObject, JsonValue } from "./protocol.js";

export type CodexFileChangeRecord = {
  path: string;
  kind?: JsonValue;
  diff?: string;
  movePath?: string;
};

const BEGIN_PATCH_MARKER = "*** Begin Patch";
const END_PATCH_MARKER = "*** End Patch";

export function normalizeCodexFileChanges(changes: unknown): CodexFileChangeRecord[] {
  if (!Array.isArray(changes)) {
    return [];
  }
  const normalized: CodexFileChangeRecord[] = [];
  for (const change of changes) {
    if (!change || typeof change !== "object" || Array.isArray(change)) {
      continue;
    }
    const record = change as Record<string, unknown>;
    const path = typeof record.path === "string" && record.path.trim() ? record.path : undefined;
    if (!path) {
      continue;
    }
    const kind = toJsonValue(record.kind);
    const diff = typeof record.diff === "string" ? record.diff : undefined;
    const movePath =
      kind && typeof kind === "object" && !Array.isArray(kind)
        ? readNonEmptyString((kind as Record<string, unknown>).move_path)
        : undefined;
    normalized.push({
      path,
      ...(kind !== undefined ? { kind } : {}),
      ...(diff !== undefined ? { diff } : {}),
      ...(movePath ? { movePath } : {}),
    });
  }
  return normalized;
}

export function buildCodexFileChangeToolParams(requestParams: JsonObject | undefined): JsonObject {
  const changes = normalizeCodexFileChanges(requestParams?.changes);
  if (changes.length === 0) {
    return requestParams ?? {};
  }
  const input = buildApplyPatchInputFromChanges(changes);
  return {
    ...(requestParams ?? {}),
    ...(input ? { input } : {}),
    changes: serializeCodexFileChanges(changes),
  };
}

export function buildCodexFileChangeEventPayload(changes: unknown): JsonObject {
  return buildCodexFileChangeToolParams({
    changes: serializeCodexFileChanges(normalizeCodexFileChanges(changes)),
  });
}

function serializeCodexFileChanges(changes: readonly CodexFileChangeRecord[]): JsonObject[] {
  return changes.map((change) => ({
    path: change.path,
    ...(change.kind !== undefined ? { kind: change.kind } : {}),
    ...(change.diff !== undefined ? { diff: change.diff } : {}),
    ...(change.movePath ? { movePath: change.movePath } : {}),
  }));
}

function buildApplyPatchInputFromChanges(changes: readonly CodexFileChangeRecord[]): string {
  const trimmedDiffs = changes
    .map((change) => change.diff?.trim())
    .filter((diff): diff is string => Boolean(diff));
  if (trimmedDiffs.length === 1 && trimmedDiffs[0]!.includes(BEGIN_PATCH_MARKER)) {
    return trimmedDiffs[0]!;
  }

  const body: string[] = [];
  for (const change of changes) {
    const kind = normalizePatchChangeKind(change.kind);
    if (kind === "add") {
      body.push(`*** Add File: ${change.path}`);
      if (change.diff?.trim()) {
        body.push(change.diff);
      }
      body.push("");
      continue;
    }
    if (kind === "delete") {
      body.push(`*** Delete File: ${change.path}`);
      body.push("");
      continue;
    }
    if (kind === "update") {
      body.push(`*** Update File: ${change.path}`);
      if (change.movePath) {
        body.push(`*** Move to: ${change.movePath}`);
      }
      if (change.diff?.trim()) {
        body.push(change.diff);
      }
      body.push("");
    }
  }
  if (body.length === 0) {
    return trimmedDiffs.join("\n\n");
  }
  return [BEGIN_PATCH_MARKER, ...body, END_PATCH_MARKER].join("\n");
}

function normalizePatchChangeKind(kind: JsonValue | undefined): string | undefined {
  if (typeof kind === "string") {
    return kind.trim() || undefined;
  }
  if (kind && typeof kind === "object" && !Array.isArray(kind)) {
    return readNonEmptyString((kind as Record<string, unknown>).type);
  }
  return undefined;
}

function readNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function toJsonValue(value: unknown): JsonValue | undefined {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (Array.isArray(value)) {
    const items = value
      .map((item) => toJsonValue(item))
      .filter((item): item is JsonValue => item !== undefined);
    return items;
  }
  if (value && typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, child] of Object.entries(value)) {
      const normalized = toJsonValue(child);
      if (normalized !== undefined) {
        result[key] = normalized;
      }
    }
    return result;
  }
  return undefined;
}
