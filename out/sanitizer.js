"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.applyEntropyMasking = exports.calculateShannonEntropy = exports.MASK = exports.stripAnsiCodes = exports.regexSanitize = exports.getFileCategory = exports.readRulesConfig = void 0;
exports.sanitizePipeline = sanitizePipeline;
exports.sanitizeOnly = sanitizeOnly;
exports.sanitizeMcpPayload = sanitizeMcpPayload;
exports.sanitizeAndCache = sanitizeAndCache;
exports.viewDiffCommand = viewDiffCommand;
const vscode = __importStar(require("vscode"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
// ── Module imports ──────────────────────────────────────────────────────────
const regexSanitizer_1 = require("./regexSanitizer");
const astSanitizer_1 = require("./astSanitizer");
const piiSanitizer_1 = require("./piiSanitizer");
const router_1 = require("./router");
// ── Re-exports for extension.ts ─────────────────────────────────────────────
var router_2 = require("./router");
Object.defineProperty(exports, "readRulesConfig", { enumerable: true, get: function () { return router_2.readRulesConfig; } });
Object.defineProperty(exports, "getFileCategory", { enumerable: true, get: function () { return router_2.getFileCategory; } });
var regexSanitizer_2 = require("./regexSanitizer");
Object.defineProperty(exports, "regexSanitize", { enumerable: true, get: function () { return regexSanitizer_2.regexSanitize; } });
Object.defineProperty(exports, "stripAnsiCodes", { enumerable: true, get: function () { return regexSanitizer_2.stripAnsiCodes; } });
Object.defineProperty(exports, "MASK", { enumerable: true, get: function () { return regexSanitizer_2.MASK; } });
Object.defineProperty(exports, "calculateShannonEntropy", { enumerable: true, get: function () { return regexSanitizer_2.calculateShannonEntropy; } });
Object.defineProperty(exports, "applyEntropyMasking", { enumerable: true, get: function () { return regexSanitizer_2.applyEntropyMasking; } });
function getPresidioApiUrl() {
    const config = vscode.workspace.getConfiguration('safechat');
    return (config.get('presidioApiUrl') || 'http://localhost:8000').replace(/\/$/, '');
}
/**
 * Calls the `/sanitize` endpoint on the running Presidio HTTP server.
 * Used only by Tier 3 (full_dlp) and terminal/search pipeline.
 */
function callPresidioApi(text, rulesConfig) {
    return new Promise((resolve, reject) => {
        const baseUrl = getPresidioApiUrl();
        let urlObj;
        try {
            urlObj = new URL('/sanitize', baseUrl);
        }
        catch {
            reject(new Error(`Invalid presidioApiUrl: ${baseUrl}`));
            return;
        }
        const payload = { text };
        if (rulesConfig?.rules && Object.keys(rulesConfig.rules).length > 0) {
            payload.rules = rulesConfig.rules;
        }
        const body = JSON.stringify(payload);
        const options = {
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
            res.on('data', (chunk) => { data += chunk.toString(); });
            res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch {
                        reject(new Error(`Invalid JSON from Presidio server: ${data.slice(0, 200)}`));
                    }
                }
                else {
                    reject(new Error(`Presidio server returned HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
                }
            });
        });
        req.on('error', (err) => {
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
function ensureHydrated(config) {
    const configHash = JSON.stringify([
        config?.custom_secrets ?? [],
        config?.sensitive_suffixes ?? [],
        config?.pii_patterns ?? {},
    ]);
    if (_hydrated && configHash === _hydratedConfigHash) {
        return;
    }
    // Tier 1: custom AST key tokens
    for (const def of config?.custom_secrets ?? []) {
        if (def.ast_keys) {
            for (const k of def.ast_keys) {
                regexSanitizer_1.DYNAMIC_AST_KEYS.add(k.toLowerCase());
            }
        }
    }
    // Tier 2: custom structural suffixes
    for (const suffix of config?.sensitive_suffixes ?? []) {
        regexSanitizer_1.SENSITIVE_SUFFIXES.add(suffix.toLowerCase());
    }
    // Local PII engine: rebuild active patterns from pii_patterns config
    (0, piiSanitizer_1.hydratePiiConfig)(config?.pii_patterns);
    _hydrated = true;
    _hydratedConfigHash = configHash;
}
/**
 * Pipeline for tool output (terminal results, search results, general text).
 * Terminal mode: stripAnsi → terminalSanitize → regexSanitize
 * General/Search: regexSanitize
 */
async function sanitizePipeline(text, mode = 'general') {
    let current = text;
    let modified = false;
    if (mode === 'terminal') {
        current = (0, regexSanitizer_1.stripAnsiCodes)(current);
        const termResult = (0, regexSanitizer_1.terminalSanitize)(current);
        current = termResult.cleanText;
        if (termResult.wasModified) {
            modified = true;
        }
    }
    const regResult = (0, regexSanitizer_1.regexSanitize)(current);
    current = regResult.cleanText;
    if (regResult.wasModified) {
        modified = true;
    }
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
async function sanitizeOnly(rawText, rulesConfig, fileName, fileSize) {
    ensureHydrated(rulesConfig);
    // ── Determine file category ─────────────────────────────────────────
    const category = fileName
        ? (0, router_1.getFileCategory)(fileName, rawText, rulesConfig)
        : 'full_dlp';
    // ── Tier 1: Bypass (source code) ────────────────────────────────────
    if (category === 'bypass') {
        return { cleanText: rawText, wasModified: false };
    }
    let current = rawText;
    let modified = false;
    let presidioError;
    // ── Tier 2: AST (structured configs) ────────────────────────────────
    // 100% synchronous — key-heuristics + local PII regex, zero API calls.
    if (category === 'ast') {
        const astFormat = fileName ? (0, router_1.getAstFormat)(fileName) : undefined;
        if (astFormat) {
            const astResult = (0, astSanitizer_1.astSanitize)(current, astFormat);
            current = astResult.cleanText;
            modified = astResult.wasModified;
        }
        else {
            // No known AST format — try Universal KV Lexer
            const kvResult = (0, astSanitizer_1.sanitizeUniversalKeyValue)(current);
            current = kvResult.cleanText;
            if (kvResult.wasModified) {
                modified = true;
            }
        }
        // Regex safety net
        const regResult = (0, regexSanitizer_1.regexSanitize)(current);
        current = regResult.cleanText;
        if (regResult.wasModified) {
            modified = true;
        }
        return { cleanText: current, wasModified: modified };
    }
    // ── Tier 3: Mega-Regex + NLP (full_dlp) ─────────────────────────────
    // Step 1: Regex dictionary + Entropy scanner
    const regResult = (0, regexSanitizer_1.regexSanitize)(current);
    current = regResult.cleanText;
    if (regResult.wasModified) {
        modified = true;
    }
    // Step 2: Presidio NLP
    try {
        const result = await callPresidioApi(current, rulesConfig);
        current = result.sanitized_text;
        if (result.was_modified) {
            modified = true;
        }
    }
    catch (err) {
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
function wildcardMatch(pattern, toolName) {
    const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
    return new RegExp(regexStr, 'i').test(toolName);
}
/**
 * Determines which MCP routing profile applies to a given tool name.
 * Iterates through all profiles and returns the first match.
 * Falls back to config.default_profile (or 'regex-only' if unset).
 */
function matchMcpProfile(toolName, config) {
    const routing = config.mcp_routing;
    if (!routing) {
        return 'regex-only';
    }
    const profileOrder = ['bypass', 'json-keys', 'regex-only', 'nlp-full'];
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
async function localRegexOnlySanitize(batch) {
    return (0, regexSanitizer_1.regexSanitize)(batch);
}
/**
 * Recursively mask values of sensitive keys in a parsed JSON object.
 * Uses `isSensitiveKey` from the AST engine to identify keys.
 * Returns true if any modifications were made.
 */
function maskSensitiveJsonKeys(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }
    let modified = false;
    if (Array.isArray(obj)) {
        for (const item of obj) {
            if (maskSensitiveJsonKeys(item)) {
                modified = true;
            }
        }
    }
    else {
        const record = obj;
        for (const key of Object.keys(record)) {
            const val = record[key];
            if (typeof val === 'string' && val.length > 0) {
                // isSensitiveKey is imported at the top of the file from regexSanitizer
                if ((0, regexSanitizer_1.isSensitiveKey)(key)) {
                    record[key] = regexSanitizer_1.MASK;
                    modified = true;
                }
            }
            else if (typeof val === 'object' && val !== null) {
                if (maskSensitiveJsonKeys(val)) {
                    modified = true;
                }
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
async function sanitizeMcpPayload(text, toolName, config) {
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
        }
        catch {
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
    const batches = [];
    for (let i = 0; i < lines.length; i += BATCH_SIZE) {
        batches.push(lines.slice(i, i + BATCH_SIZE).join('\n'));
    }
    const results = await Promise.all(batches.map(batch => localRegexOnlySanitize(batch)));
    let wasModified = false;
    const sanitizedBatches = [];
    for (const result of results) {
        sanitizedBatches.push(result.cleanText);
        if (result.wasModified) {
            wasModified = true;
        }
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
let latestCacheEntryUri;
/** Returns the root `.vscode/.temp_cache` base directory URI. */
function getCacheBaseUri() {
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
function timestampSlug() {
    const now = new Date();
    const pad = (n, len = 2) => String(n).padStart(len, '0');
    return (`${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
        `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}` +
        `-${pad(now.getMilliseconds(), 3)}`);
}
/**
 * Ensures the base cache root exists and contains a wildcard .gitignore.
 * Only writes the .gitignore once (cheap stat-check first).
 */
async function ensureCacheRoot(baseUri) {
    await vscode.workspace.fs.createDirectory(baseUri);
    const gitignoreUri = vscode.Uri.joinPath(baseUri, '.gitignore');
    try {
        await vscode.workspace.fs.stat(gitignoreUri);
    }
    catch {
        // Doesn't exist yet — create it.
        await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from('*\n', 'utf-8'));
    }
}
/**
 * Sanitize `rawText`, cache original + masked versions for diffing, and
 * return the clean text together with a modification flag.
 *
 * Uses the Smart Router: routes through getFileCategory to determine which
 * sanitization tier applies.
 */
async function sanitizeAndCache(rawText, _extensionPath, fileName) {
    const rulesConfig = await (0, router_1.readRulesConfig)();
    const { cleanText, wasModified, presidioError } = await sanitizeOnly(rawText, rulesConfig, fileName);
    if (wasModified) {
        const baseUri = getCacheBaseUri();
        if (baseUri) {
            await ensureCacheRoot(baseUri);
            const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
            await vscode.workspace.fs.createDirectory(entryDir);
            const originalUri = vscode.Uri.joinPath(entryDir, 'original_context.txt');
            const maskedUri = vscode.Uri.joinPath(entryDir, 'masked_context.txt');
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
async function viewDiffCommand(entryUriString) {
    if (entryUriString) {
        const entryUri = vscode.Uri.parse(entryUriString);
        const originalUri = vscode.Uri.joinPath(entryUri, 'original_context.txt');
        const maskedUri = vscode.Uri.joinPath(entryUri, 'masked_context.txt');
        await vscode.commands.executeCommand('vscode.diff', originalUri, maskedUri, `Original ↔ Sanitized  [${entryUri.path.split('/').pop()}]`);
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
            }
            catch {
                // base dir not created yet — fall through to the warning below.
            }
        }
    }
    if (!latestCacheEntryUri) {
        vscode.window.showWarningMessage('SafeChat: No cached diff available yet. Attach a file to @safechat first.');
        return;
    }
    const originalUri = vscode.Uri.joinPath(latestCacheEntryUri, 'original_context.txt');
    const maskedUri = vscode.Uri.joinPath(latestCacheEntryUri, 'masked_context.txt');
    await vscode.commands.executeCommand('vscode.diff', originalUri, maskedUri, `Original ↔ Sanitized  [${latestCacheEntryUri.path.split('/').pop()}]`);
}
//# sourceMappingURL=sanitizer.js.map