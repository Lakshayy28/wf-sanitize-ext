"use strict";
/**
 * sanitizer.ts — Thin Orchestrator (Server-Delegated)
 * =====================================================
 * Routes files via the 3-Tier Smart Router, then delegates ALL masking
 * to the Python Heavy Brain server via /api/sanitize/batch.
 *
 *   Tier 1 (Bypass)  → source code, passed raw
 *   Tier 2 (AST)     → structured configs → AST parsers extract values → server masks them
 *   Tier 3 (Full DLP)→ raw text sent to server in one shot
 *
 * ZERO sanitization logic lives here — the server runs Presidio NLP + regex + entropy.
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
exports.applyEntropyMasking = exports.calculateShannonEntropy = exports.MASK = exports.stripAnsiCodes = exports.getFileCategory = exports.readRulesConfig = void 0;
exports.sanitizePipeline = sanitizePipeline;
exports.sanitizeOnly = sanitizeOnly;
exports.sanitizeAndCache = sanitizeAndCache;
exports.viewDiffCommand = viewDiffCommand;
const vscode = __importStar(require("vscode"));
// ── Module imports ──────────────────────────────────────────────────────────
const apiClient_1 = require("./apiClient");
const regexSanitizer_1 = require("./regexSanitizer");
const astSanitizer_1 = require("./astSanitizer");
const router_1 = require("./router");
// ── Re-exports for extension.ts ─────────────────────────────────────────────
var router_2 = require("./router");
Object.defineProperty(exports, "readRulesConfig", { enumerable: true, get: function () { return router_2.readRulesConfig; } });
Object.defineProperty(exports, "getFileCategory", { enumerable: true, get: function () { return router_2.getFileCategory; } });
var regexSanitizer_2 = require("./regexSanitizer");
Object.defineProperty(exports, "stripAnsiCodes", { enumerable: true, get: function () { return regexSanitizer_2.stripAnsiCodes; } });
Object.defineProperty(exports, "MASK", { enumerable: true, get: function () { return regexSanitizer_2.MASK; } });
Object.defineProperty(exports, "calculateShannonEntropy", { enumerable: true, get: function () { return regexSanitizer_2.calculateShannonEntropy; } });
Object.defineProperty(exports, "applyEntropyMasking", { enumerable: true, get: function () { return regexSanitizer_2.applyEntropyMasking; } });
// ────────────────────────────────────────────────────────────────────────────
// Server availability gate (cached health check)
// ────────────────────────────────────────────────────────────────────────────
let _healthCacheTime = 0;
let _healthCacheResult = false;
const HEALTH_CACHE_TTL = 5_000; // 5 seconds
/**
 * Cached server health check. Returns true if the Heavy Brain server is
 * reachable, false otherwise. Re-checks at most every 5 seconds.
 */
async function isServerAvailable() {
    const now = Date.now();
    if (now - _healthCacheTime < HEALTH_CACHE_TTL) {
        return _healthCacheResult;
    }
    _healthCacheResult = await (0, apiClient_1.checkServerHealth)();
    _healthCacheTime = now;
    return _healthCacheResult;
}
// ────────────────────────────────────────────────────────────────────────────
// Hydration bootstrap — inject custom AST keys from YAML config
// ────────────────────────────────────────────────────────────────────────────
let _hydrated = false;
let _hydratedConfigHash = '';
function ensureHydrated(config) {
    const configHash = JSON.stringify(config?.custom_secrets ?? []);
    if (_hydrated && configHash === _hydratedConfigHash) {
        return;
    }
    if (!config?.custom_secrets) {
        _hydrated = true;
        _hydratedConfigHash = configHash;
        return;
    }
    // Only push custom AST keys (server handles the regex patterns)
    for (const def of config.custom_secrets) {
        if (def.ast_keys) {
            for (const k of def.ast_keys) {
                const lower = k.toLowerCase();
                if (!regexSanitizer_1.DYNAMIC_AST_KEYS.includes(lower)) {
                    regexSanitizer_1.DYNAMIC_AST_KEYS.push(lower);
                }
            }
        }
    }
    _hydrated = true;
    _hydratedConfigHash = configHash;
}
// ────────────────────────────────────────────────────────────────────────────
// Config → Server payload helpers
// ────────────────────────────────────────────────────────────────────────────
function buildRecognizerPayloads(config) {
    if (!config?.custom_recognizers?.length) {
        return undefined;
    }
    return config.custom_recognizers.map(r => ({
        name: r.name,
        pattern: r.pattern,
        score: r.score,
        context: r.context,
    }));
}
function buildSecretPayloads(config) {
    if (!config?.custom_secrets?.length) {
        return undefined;
    }
    return config.custom_secrets
        .filter(s => s.value_prefix) // Only send secrets that have regex-buildable definitions
        .map(s => ({
        name: s.name,
        value_prefix: s.value_prefix,
        value_charset: s.value_charset,
        value_length: s.value_length,
    }));
}
/**
 * Pipeline for tool output (terminal results, search results, general text).
 * Sends raw text to the server for full sanitization.
 * Terminal mode: strips ANSI codes first.
 */
async function sanitizePipeline(text, mode = 'general') {
    let current = text;
    if (mode === 'terminal') {
        current = (0, regexSanitizer_1.stripAnsiCodes)(current);
    }
    // Server availability gate
    if (!(await isServerAvailable())) {
        console.log('[SafeChat] sanitizePipeline: server unavailable, returning text as-is');
        return { cleanText: current, wasModified: false };
    }
    try {
        const { sanitized, wasModified } = await (0, apiClient_1.sanitizeOne)(current);
        return { cleanText: sanitized, wasModified };
    }
    catch {
        // Server unreachable — return text as-is (fail-open for tool output)
        return { cleanText: current, wasModified: false };
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Smart Router — File-level sanitization (the main entry point)
// ────────────────────────────────────────────────────────────────────────────
/**
 * 3-Tier Smart Router (Server-Delegated):
 *
 *  Tier 1 (bypass):        source code → pass raw
 *  Tier 2 (ast):           structured configs → AST extract values → server masks
 *  Tier 2B (universal-kv): unknown KV files → Universal Lexer + server masks
 *  Tier 3 (full_dlp):      everything else → send raw text to server
 *
 * If `fileName` is omitted (e.g., user prompt text), defaults to Tier 3.
 */
async function sanitizeOnly(rawText, rulesConfig, fileName, fileSize) {
    ensureHydrated(rulesConfig);
    // ── Server availability gate — ALL masking requires the server ──────
    if (!(await isServerAvailable())) {
        return {
            cleanText: rawText,
            wasModified: false,
            presidioError: 'Presidio server is not available. Start it with: uvicorn presidio_server.main:app --port 8000',
        };
    }
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
    // Build server payloads from config (sent with every server call)
    const recognizerPayloads = buildRecognizerPayloads(rulesConfig);
    const secretPayloads = buildSecretPayloads(rulesConfig);
    // PII checker callback for AST parsers — delegates to server
    const piiCheck = async (value) => {
        try {
            const { sanitized } = await (0, apiClient_1.sanitizeOne)(value, undefined, rulesConfig?.rules, recognizerPayloads, secretPayloads);
            return sanitized;
        }
        catch (err) {
            if (!presidioError) {
                presidioError = err instanceof Error ? err.message : String(err);
            }
            return value;
        }
    };
    // ── Tier 2: AST (structured configs) ────────────────────────────────
    if (category === 'ast') {
        const astFormat = fileName ? (0, router_1.getAstFormat)(fileName) : undefined;
        if (astFormat) {
            const astResult = await (0, astSanitizer_1.astSanitize)(current, astFormat, piiCheck);
            current = astResult.cleanText;
            modified = astResult.wasModified;
        }
        else {
            // No known AST format — try Universal KV Lexer
            const kvResult = await (0, astSanitizer_1.sanitizeUniversalKeyValue)(current);
            current = kvResult.cleanText;
            if (kvResult.wasModified) {
                modified = true;
            }
        }
        // Server safety net — catch any secrets the AST pass missed
        try {
            const { sanitized, wasModified: serverModified } = await (0, apiClient_1.sanitizeOne)(current, undefined, rulesConfig?.rules, recognizerPayloads, secretPayloads);
            current = sanitized;
            if (serverModified) {
                modified = true;
            }
        }
        catch (err) {
            if (!presidioError) {
                presidioError = err instanceof Error ? err.message : String(err);
            }
        }
        return { cleanText: current, wasModified: modified, presidioError };
    }
    // ── Tier 3: Full DLP — send raw text to server ──────────────────────
    try {
        const { sanitized, wasModified: serverModified } = await (0, apiClient_1.sanitizeOne)(current, undefined, rulesConfig?.rules, recognizerPayloads, secretPayloads);
        current = sanitized;
        if (serverModified) {
            modified = true;
        }
    }
    catch (err) {
        presidioError = err instanceof Error ? err.message : String(err);
    }
    return { cleanText: current, wasModified: modified, presidioError };
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