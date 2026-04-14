/**
 * sanitizer.ts — Thin Orchestrator
 * =================================
 * Wires the 3-Tier Smart Routing Architecture together:
 *
 *   Tier 1 (Bypass)  → source code, passed raw
 *   Tier 2 (AST)     → structured configs → astSanitizer + regexSanitize fallback
 *   Tier 3 (Full DLP)→ unstructured text → regexSanitize + Presidio NLP
 *
 * Re-exports all types and functions that extension.ts needs.
 */

import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';

// ── Module imports ──────────────────────────────────────────────────────────
import { regexSanitize, terminalSanitize, stripAnsiCodes, hydrateCustomSecrets, MASK, applyEntropyMasking, DYNAMIC_AST_KEYS, SENSITIVE_SUFFIXES, isSensitiveKey } from './regexSanitizer';
import { astSanitize, sanitizeUniversalKeyValue, type AstFormat } from './astSanitizer';
import { hydratePiiConfig } from './piiSanitizer';
import {
  getFileCategory, getAstFormat, readRulesConfig,
  type RulesConfig, type FileCategory, type CustomSecretDef,
  type McpRoutingConfig, type McpRoutingProfile,
} from './router';

// ── Re-exports for extension.ts ─────────────────────────────────────────────
export { readRulesConfig, getFileCategory } from './router';
export type { RulesConfig, FileCategory, CustomSecretDef, McpRoutingConfig, McpRoutingProfile } from './router';
export { regexSanitize, stripAnsiCodes, MASK, calculateShannonEntropy, applyEntropyMasking } from './regexSanitizer';
export type { SecretPattern } from './regexSanitizer';

// ────────────────────────────────────────────────────────────────────────────
// Presidio HTTP bridge (Tier 3 only — NLP PII masking)
// ────────────────────────────────────────────────────────────────────────────

interface SanitizeResponse {
  sanitized_text: string;
  was_modified: boolean;
  entities_found: Array<{ entity_type: string; start: number; end: number; score: number }>;
}

function getPresidioApiUrl(): string {
  const config = vscode.workspace.getConfiguration('safechat');
  return (config.get<string>('presidioApiUrl') || 'http://localhost:8000').replace(/\/$/, '');
}

/**
 * Calls the `/sanitize` endpoint on the running Presidio HTTP server.
 * Used only by Tier 3 (full_dlp) and terminal/search pipeline.
 */
function callPresidioApi(text: string, rulesConfig?: RulesConfig): Promise<SanitizeResponse> {
  return new Promise((resolve, reject) => {
    const baseUrl = getPresidioApiUrl();
    let urlObj: URL;
    try {
      urlObj = new URL('/sanitize', baseUrl);
    } catch {
      reject(new Error(`Invalid presidioApiUrl: ${baseUrl}`));
      return;
    }

    const payload: Record<string, unknown> = { text };
    if (rulesConfig?.rules && Object.keys(rulesConfig.rules).length > 0) {
      payload.rules = rulesConfig.rules;
    }
    const body = JSON.stringify(payload);
    const options: http.RequestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const transport = urlObj.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data) as SanitizeResponse);
          } catch {
            reject(new Error(`Invalid JSON from Presidio server: ${data.slice(0, 200)}`));
          }
        } else {
          reject(new Error(`Presidio server returned HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', (err: Error) => {
      reject(new Error(`Presidio server unreachable at ${baseUrl}: ${err.message}`));
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Presidio server request timed out after 10 s'));
    });

    req.write(body);
    req.end();
  });
}

// ────────────────────────────────────────────────────────────────────────────
// Hydration bootstrap — run once when config is first loaded
// ────────────────────────────────────────────────────────────────────────────

let _hydrated = false;
let _hydratedConfigHash = '';

function ensureHydrated(config?: RulesConfig): void {
  const configHash = JSON.stringify([
    config?.custom_secrets ?? [],
    config?.sensitive_suffixes ?? [],
    config?.pii_patterns ?? {},
  ]);
  if (_hydrated && configHash === _hydratedConfigHash) { return; }
  // Tier 1: custom AST key tokens
  for (const def of config?.custom_secrets ?? []) {
    if (def.ast_keys) {
      for (const k of def.ast_keys) {
        DYNAMIC_AST_KEYS.add(k.toLowerCase());
      }
    }
  }
  // Tier 2: custom structural suffixes
  for (const suffix of config?.sensitive_suffixes ?? []) {
    SENSITIVE_SUFFIXES.add(suffix.toLowerCase());
  }
  // Local PII engine: rebuild active patterns from pii_patterns config
  hydratePiiConfig(config?.pii_patterns);
  _hydrated = true;
  _hydratedConfigHash = configHash;
}

// ────────────────────────────────────────────────────────────────────────────
// Unified Sanitization Pipeline (tool output — terminal, search, general)
// ────────────────────────────────────────────────────────────────────────────

export type SanitizeMode = 'terminal' | 'general' | 'search';

/**
 * Pipeline for tool output (terminal results, search results, general text).
 * Terminal mode: stripAnsi → terminalSanitize → regexSanitize
 * General/Search: regexSanitize
 */
export async function sanitizePipeline(
  text: string,
  mode: SanitizeMode = 'general',
): Promise<{ cleanText: string; wasModified: boolean }> {
  let current = text;
  let modified = false;

  if (mode === 'terminal') {
    current = stripAnsiCodes(current);
    const termResult = terminalSanitize(current);
    current = termResult.cleanText;
    if (termResult.wasModified) { modified = true; }
  }

  const regResult = regexSanitize(current);
  current = regResult.cleanText;
  if (regResult.wasModified) { modified = true; }

  return { cleanText: current, wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Smart Router — File-level sanitization (the main entry point)
// ────────────────────────────────────────────────────────────────────────────

/**
 * 3-Tier Smart Router:
 *
 *  Tier 1 (bypass):        source code → pass raw
 *  Tier 2 (ast):           structured configs → AST key-match + regex fallback
 *  Tier 2B (universal-kv): unknown KV files → Universal Lexer + regex
 *  Tier 3 (full_dlp):      everything else → regex + Presidio NLP
 *
 * If `fileName` is omitted (e.g., user prompt text), defaults to Tier 3.
 */
export async function sanitizeOnly(
  rawText: string,
  rulesConfig?: RulesConfig,
  fileName?: string,
  fileSize?: number,
): Promise<{
  cleanText: string;
  wasModified: boolean;
  presidioError?: string;
}> {
  ensureHydrated(rulesConfig);

  // ── Determine file category ─────────────────────────────────────────
  const category: FileCategory = fileName
    ? getFileCategory(fileName, rawText, rulesConfig)
    : 'full_dlp';

  // ── Tier 1: Bypass (source code) ────────────────────────────────────
  if (category === 'bypass') {
    return { cleanText: rawText, wasModified: false };
  }

  let current = rawText;
  let modified = false;
  let presidioError: string | undefined;

  // ── Tier 2: AST (structured configs) ────────────────────────────────
  // 100% synchronous — key-heuristics + local PII regex, zero API calls.
  if (category === 'ast') {
    const astFormat = fileName ? getAstFormat(fileName) : undefined;
    if (astFormat) {
      const astResult = astSanitize(current, astFormat);
      current = astResult.cleanText;
      modified = astResult.wasModified;
    } else {
      // No known AST format — try Universal KV Lexer
      const kvResult = sanitizeUniversalKeyValue(current);
      current = kvResult.cleanText;
      if (kvResult.wasModified) { modified = true; }
    }

    // Regex safety net
    const regResult = regexSanitize(current);
    current = regResult.cleanText;
    if (regResult.wasModified) { modified = true; }

    return { cleanText: current, wasModified: modified };
  }

  // ── Tier 3: Mega-Regex + NLP (full_dlp) ─────────────────────────────
  // Step 1: Regex dictionary + Entropy scanner
  const regResult = regexSanitize(current);
  current = regResult.cleanText;
  if (regResult.wasModified) { modified = true; }

  // Step 2: Presidio NLP
  try {
    const result = await callPresidioApi(current, rulesConfig);
    current = result.sanitized_text;
    if (result.was_modified) { modified = true; }
  } catch (err) {
    presidioError = err instanceof Error ? err.message : String(err);
  }

  return { cleanText: current, wasModified: modified, presidioError };
}

// ────────────────────────────────────────────────────────────────────────────
// MCP Triage Router — Zero-Trust interception for MCP tool payloads
// ────────────────────────────────────────────────────────────────────────────

/**
 * Matches a tool name against a single wildcard glob pattern (case-insensitive).
 * Supports `*` as a wildcard that matches any sequence of characters.
 * e.g. "*weather*" matches "mcp_test_weather", "myWeatherApi", etc.
 */
function wildcardMatch(pattern: string, toolName: string): boolean {
  const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
  return new RegExp(regexStr, 'i').test(toolName);
}

/**
 * Determines which MCP routing profile applies to a given tool name.
 * Iterates through all profiles and returns the first match.
 * Falls back to config.default_profile (or 'regex-only' if unset).
 */
function matchMcpProfile(toolName: string, config: RulesConfig): McpRoutingProfile {
  const routing = config.mcp_routing;
  if (!routing) { return 'regex-only'; }

  const profileOrder: McpRoutingProfile[] = ['bypass', 'json-keys', 'regex-only', 'nlp-full'];
  for (const profile of profileOrder) {
    const patterns = routing.profiles[profile];
    if (patterns && patterns.some(p => wildcardMatch(p, toolName))) {
      return profile;
    }
  }

  return routing.default_profile || 'regex-only';
}

/**
 * Regex-only sanitization for a single batch of text (line-joined).
 * Wraps `regexSanitize` to match the async batch interface.
 */
async function localRegexOnlySanitize(
  batch: string,
): Promise<{ cleanText: string; wasModified: boolean }> {
  return regexSanitize(batch);
}

/**
 * Recursively mask values of sensitive keys in a parsed JSON object.
 * Uses `isSensitiveKey` from the AST engine to identify keys.
 * Returns true if any modifications were made.
 */
function maskSensitiveJsonKeys(obj: unknown): boolean {
  if (typeof obj !== 'object' || obj === null) { return false; }
  let modified = false;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (maskSensitiveJsonKeys(item)) { modified = true; }
    }
  } else {
    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const val = record[key];
      if (typeof val === 'string' && val.length > 0) {
        // isSensitiveKey is imported at the top of the file from regexSanitizer
        if (isSensitiveKey(key)) {
          record[key] = MASK;
          modified = true;
        }
      } else if (typeof val === 'object' && val !== null) {
        if (maskSensitiveJsonKeys(val)) { modified = true; }
      }
    }
  }

  return modified;
}

/**
 * MCP Triage Router — sanitizes MCP tool payloads based on the routing profile
 * matched from the tool name against `safechat-rules.yaml` config.
 *
 * Profiles:
 *   bypass    — pass through immediately (safe tools like weather, calc)
 *   json-keys — parse JSON, mask sensitive key values, re-serialize
 *   regex-only — semantic line-batching with truncation + concurrent regex
 *   nlp-full  — full DLP pipeline (regex + Shannon entropy + Presidio NLP)
 *
 * The `regex-only` profile implements:
 *   1. Line splitting (never splits a credential in half)
 *   2. Contextual truncation (>5000 lines → first 2500 + last 2500 + warning)
 *   3. Concurrent batching (500 lines/batch via Promise.all)
 */
export async function sanitizeMcpPayload(
  text: string,
  toolName: string,
  config: RulesConfig,
): Promise<{ cleanText: string; wasModified: boolean }> {
  const profile = matchMcpProfile(toolName, config);
  console.log(`[SafeChat] MCP Router: tool="${toolName}" → profile="${profile}"`);

  ensureHydrated(config);

  // ── bypass ────────────────────────────────────────────────────────────
  if (profile === 'bypass') {
    return { cleanText: text, wasModified: false };
  }

  // ── json-keys ─────────────────────────────────────────────────────────
  if (profile === 'json-keys') {
    try {
      const parsed = JSON.parse(text);
      const wasModified = maskSensitiveJsonKeys(parsed);
      return { cleanText: JSON.stringify(parsed, null, 2), wasModified };
    } catch {
      // JSON parse failed — fall through to regex-only
      console.log(`[SafeChat] MCP json-keys: JSON.parse failed for ${toolName}, falling back to regex-only`);
    }
  }

  // ── nlp-full ──────────────────────────────────────────────────────────
  if (profile === 'nlp-full') {
    return sanitizePipeline(text, 'general');
  }

  // ── regex-only (Semantic Line-Batching) ───────────────────────────────
  let lines = text.split('\n');

  // Step 1: Contextual Truncation
  if (lines.length > 5000) {
    const totalLines = lines.length;
    const head = lines.slice(0, 2500);
    const tail = lines.slice(-2500);
    const warningLine = `[... TRUNCATED ${totalLines - 5000} LINES FOR CONTEXT/SANITIZATION LIMITS ...]`;
    lines = [...head, warningLine, ...tail];
    console.log(`[SafeChat] MCP regex-only: truncated ${totalLines} → ${lines.length} lines`);
  }

  // Step 2: Concurrent Batching (500 lines per batch)
  const BATCH_SIZE = 500;
  const batches: string[] = [];
  for (let i = 0; i < lines.length; i += BATCH_SIZE) {
    batches.push(lines.slice(i, i + BATCH_SIZE).join('\n'));
  }

  const results = await Promise.all(
    batches.map(batch => localRegexOnlySanitize(batch)),
  );

  let wasModified = false;
  const sanitizedBatches: string[] = [];
  for (const result of results) {
    sanitizedBatches.push(result.cleanText);
    if (result.wasModified) { wasModified = true; }
  }

  return { cleanText: sanitizedBatches.join('\n'), wasModified };
}

// ────────────────────────────────────────────────────────────────────────────
// Cache directory helpers
// ────────────────────────────────────────────────────────────────────────────

/**
 * In-memory pointer to the most recently written cache entry.
 * Used by viewDiffCommand so the button always opens the latest diff.
 */
let latestCacheEntryUri: vscode.Uri | undefined;

/** Returns the root `.vscode/.temp_cache` base directory URI. */
function getCacheBaseUri(): vscode.Uri | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return undefined;
  }
  return vscode.Uri.joinPath(folders[0].uri, '.vscode', '.temp_cache');
}

/**
 * Generates a filesystem-safe timestamp string for use as a subfolder name.
 * e.g. "2026-03-21_10-30-00-042"
 */
function timestampSlug(): string {
  const now = new Date();
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
    `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
    `-${pad(now.getMilliseconds(), 3)}`
  );
}

/**
 * Ensures the base cache root exists and contains a wildcard .gitignore.
 * Only writes the .gitignore once (cheap stat-check first).
 */
async function ensureCacheRoot(baseUri: vscode.Uri): Promise<void> {
  await vscode.workspace.fs.createDirectory(baseUri);

  const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
  try {
    await vscode.workspace.fs.stat(gitignoreUri);
  } catch {
    // Doesn't exist yet — create it.
    await vscode.workspace.fs.writeFile(
      gitignoreUri,
      Buffer.from('*\n', 'utf-8')
    );
  }
}

/**
 * Sanitize `rawText`, cache original + masked versions for diffing, and
 * return the clean text together with a modification flag.
 *
 * Uses the Smart Router: routes through getFileCategory to determine which
 * sanitization tier applies.
 */
export async function sanitizeAndCache(
  rawText: string,
  _extensionPath?: string,
  fileName?: string,
): Promise<{
  cleanText: string;
  wasModified: boolean;
  cacheEntryUri?: vscode.Uri;
  presidioError?: string;
}> {
  const rulesConfig = await readRulesConfig();
  const { cleanText, wasModified, presidioError } = await sanitizeOnly(rawText, rulesConfig, fileName);

  if (wasModified) {
    const baseUri = getCacheBaseUri();
    if (baseUri) {
      await ensureCacheRoot(baseUri);

      const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
      await vscode.workspace.fs.createDirectory(entryDir);

      const originalUri = vscode.Uri.joinPath(entryDir, 'original_context.txt');
      const maskedUri   = vscode.Uri.joinPath(entryDir, 'masked_context.txt');

      await Promise.all([
        vscode.workspace.fs.writeFile(originalUri, Buffer.from(rawText, 'utf-8')),
        vscode.workspace.fs.writeFile(maskedUri, Buffer.from(cleanText, 'utf-8')),
      ]);

      latestCacheEntryUri = entryDir;

      return { cleanText, wasModified, cacheEntryUri: entryDir, presidioError };
    }
  }

  return { cleanText, wasModified, presidioError };
}

/**
 * Opens the VS Code diff editor comparing the original and masked context files.
 * Bound to the `safecopilot.viewDiff` command.
 */
export async function viewDiffCommand(entryUriString?: string): Promise<void> {
  if (entryUriString) {
    const entryUri = vscode.Uri.parse(entryUriString);
    const originalUri = vscode.Uri.joinPath(entryUri, 'original_context.txt');
    const maskedUri   = vscode.Uri.joinPath(entryUri, 'masked_context.txt');
    await vscode.commands.executeCommand(
      'vscode.diff',
      originalUri,
      maskedUri,
      `Original ↔ Sanitized  [${entryUri.path.split('/').pop()}]`
    );
    return;
  }

  if (!latestCacheEntryUri) {
    const baseUri = getCacheBaseUri();
    if (baseUri) {
      try {
        const entries = await vscode.workspace.fs.readDirectory(baseUri);
        const dirs = entries
          .filter(([, type]) => type === vscode.FileType.Directory)
          .map(([name]) => name)
          .sort()
          .reverse();
        if (dirs.length > 0) {
          latestCacheEntryUri = vscode.Uri.joinPath(baseUri, dirs[0]);
        }
      } catch {
        // base dir not created yet — fall through to the warning below.
      }
    }
  }

  if (!latestCacheEntryUri) {
    vscode.window.showWarningMessage(
      'SafeChat: No cached diff available yet. Attach a file to @safechat first.'
    );
    return;
  }

  const originalUri = vscode.Uri.joinPath(latestCacheEntryUri, 'original_context.txt');
  const maskedUri   = vscode.Uri.joinPath(latestCacheEntryUri, 'masked_context.txt');

  await vscode.commands.executeCommand(
    'vscode.diff',
    originalUri,
    maskedUri,
    `Original ↔ Sanitized  [${latestCacheEntryUri.path.split('/').pop()}]`
  );
}
