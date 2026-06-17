import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { OpenClawPluginApi } from "../../../src/plugins/types.js";

const GUARD_API_KEY_HEADER = "X-Guard-API-Key";
const GUARD_CREDENTIAL_FILE_ENV = "GUARD_OPENCLAW_CREDENTIAL_FILE";

type GuardCredential = {
  version?: number;
  endpoint?: string;
  header?: string;
  apiKey?: string;
  createdAt?: string;
  pid?: number;
};

type GuardCredentialCacheEntry = {
  file: string;
  header: string;
  apiKey: string;
};

export type GuardHTTPConfig = {
  endpoint: string;
  timeoutMs: number;
  credentialFile?: string;
};

const credentialCache = new Map<string, GuardCredentialCacheEntry>();

export function defaultGuardCredentialFile(): string {
  const dataDir = process.env.GUARD_DATA_DIR?.trim();
  if (dataDir) {
    return path.join(expandHome(dataDir), "runtime", "openclaw-client.json");
  }
  return path.join(os.homedir(), ".config", "guard", "runtime", "openclaw-client.json");
}

export function resolveGuardCredentialFile(configured?: string): string {
  const raw = configured?.trim() || process.env[GUARD_CREDENTIAL_FILE_ENV]?.trim();
  if (raw) {
    return expandHome(raw);
  }
  return defaultGuardCredentialFile();
}

export function guardAuthErrorMessage(configured?: string): string {
  const file = resolveGuardCredentialFile(configured);
  return (
    "Guard API authentication failed. Start guardd so it can write " +
    `${file}, or set ${GUARD_CREDENTIAL_FILE_ENV}/guard.config.credentialFile to the handoff path.`
  );
}

export function clearGuardAuthCacheForTests() {
  credentialCache.clear();
}

export async function fetchGuardApi(
  api: OpenClawPluginApi,
  cfg: GuardHTTPConfig,
  requestPath: string,
  init: RequestInit,
): Promise<Response> {
  const url = `${cfg.endpoint}${requestPath}`;
  const attempt = async (forceReload: boolean) => {
    const authHeaders = await loadGuardAuthHeaders(api, cfg.credentialFile, forceReload);
    return fetch(url, {
      ...init,
      headers: {
        ...normalizeHeaders(init.headers),
        ...authHeaders,
      },
    });
  };

  const first = await attempt(false);
  if (first.status !== 401) {
    return first;
  }
  return attempt(true);
}

async function loadGuardAuthHeaders(
  api: OpenClawPluginApi,
  configured: string | undefined,
  forceReload: boolean,
): Promise<Record<string, string>> {
  const file = resolveGuardCredentialFile(configured);
  if (!forceReload) {
    const cached = credentialCache.get(file);
    if (cached) {
      return { [cached.header]: cached.apiKey };
    }
  }

  try {
    const credential = await readGuardCredential(file);
    if (!credential) {
      credentialCache.delete(file);
      return {};
    }
    credentialCache.set(file, credential);
    return { [credential.header]: credential.apiKey };
  } catch (err) {
    credentialCache.delete(file);
    api.logger.debug?.(`guard: could not read credential file ${file}: ${String(err)}`);
    return {};
  }
}

async function readGuardCredential(file: string): Promise<GuardCredentialCacheEntry | null> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }

  const parsed = JSON.parse(raw) as GuardCredential;
  const apiKey = typeof parsed.apiKey === "string" ? parsed.apiKey.trim() : "";
  if (!apiKey) {
    return null;
  }
  const header =
    typeof parsed.header === "string" && parsed.header.trim()
      ? parsed.header.trim()
      : GUARD_API_KEY_HEADER;
  return { file, header, apiKey };
}

function expandHome(value: string): string {
  if (value === "~") {
    return os.homedir();
  }
  if (value.startsWith("~/")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

function normalizeHeaders(headers: HeadersInit | undefined): Record<string, string> {
  if (!headers) {
    return {};
  }
  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }
  return { ...headers };
}
