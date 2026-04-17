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
exports.escapeMcpMarkdown = escapeMcpMarkdown;
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
    // Fix 3 (Homoglyph Normalization): Apply NFKD Unicode normalization before regex scanning.
    // NFKD decomposes homoglyphs (e.g. Cyrillic 'а' U+0430 → 'a') and compatibility characters.
    // Without this, an attacker can use lookalike code points to evade `isSensitiveKey` heuristics
    // and every regex pattern (e.g. `pаssword` with Cyrillic 'а' bypasses /password/i).
    // We normalize for scanning but preserve the original text as output — masking
    // operates on the original string using the positions discovered via the normalized copy.
    // For the pipeline mode (tool output streams), normalizing-in-place is safe because
    // these payloads are ephemeral context sent to the LLM, not written back to disk.
    const normalizedForScan = current.normalize('NFKD');
    const regResult = (0, regexSanitizer_1.regexSanitize)(normalizedForScan);
    // If masking occurred on the normalized copy, we must also run it on the original
    // to ensure the raw output is cleaned. For consistency, forward the normalized+masked text.
    if (regResult.wasModified) {
        current = regResult.cleanText;
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
        // Fix 3: Fail CLOSED for full_dlp — Presidio is mandatory at this tier.
        // Returning regex-only text would silently drop NLP PII detection.
        // Block the payload entirely so the failure is visible to the user.
        return {
            cleanText: `[SAFECHAT BLOCK: Presidio NLP scanner failed. Payload blocked for security.]\n` +
                `Error Details: ${presidioError}\n` +
                `Resolution: Ensure the local Presidio server is running on port 8000.`,
            wasModified: true,
            presidioError,
        };
    }
    return { cleanText: current, wasModified: modified, presidioError };
}
// ────────────────────────────────────────────────────────────────────────────
// MCP Triage Router — Zero-Trust interception for MCP tool payloads
// ────────────────────────────────────────────────────────────────────────────
// Fixes BUG-9: Strict byte budget to prevent LLM context window overflow
const MAX_PAYLOAD_BYTES = 80_000; // ~20K tokens — safe for Copilot context
// Fixes BUG-7: Skip catastrophic-backtracking-prone regex patterns on large inputs
const MAX_REGEX_SAFE_BYTES = 50_000;
// Fixes BUG-11: Prevent stack overflow on deeply nested JSON
const MAX_JSON_DEPTH = 30;
// Fixes BUG-8: Cache compiled RegExp objects for wildcard matching
const wildcardCache = new Map();
/**
 * Matches a tool name against a single wildcard glob pattern (case-insensitive).
 * Fixes BUG-8: Caches compiled RegExp to avoid recompilation per call.
 */
function wildcardMatch(pattern, toolName) {
    let re = wildcardCache.get(pattern);
    if (!re) {
        const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
        re = new RegExp(regexStr, 'i');
        wildcardCache.set(pattern, re);
    }
    return re.test(toolName);
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
 * Regex-only sanitization wrapper with backtracking safety guard.
 * Fixes BUG-7: For payloads exceeding MAX_REGEX_SAFE_BYTES, processes
 * in smaller line-based chunks to prevent catastrophic backtracking in
 * multi-line patterns (GCP Service Account, RSA/PEM Private Key).
 */
function safeRegexSanitize(text) {
    if (text.length <= MAX_REGEX_SAFE_BYTES) {
        return (0, regexSanitizer_1.regexSanitize)(text);
    }
    // For large payloads: split into safe-sized line-based chunks,
    // process each independently to isolate backtracking scope
    const lines = text.split('\n');
    let modified = false;
    const chunks = [];
    let currentChunk = [];
    let currentSize = 0;
    for (const line of lines) {
        if (currentSize + line.length > MAX_REGEX_SAFE_BYTES && currentChunk.length > 0) {
            const result = (0, regexSanitizer_1.regexSanitize)(currentChunk.join('\n'));
            chunks.push(result.cleanText);
            if (result.wasModified) {
                modified = true;
            }
            currentChunk = [];
            currentSize = 0;
        }
        currentChunk.push(line);
        currentSize += line.length + 1;
    }
    if (currentChunk.length > 0) {
        const result = (0, regexSanitizer_1.regexSanitize)(currentChunk.join('\n'));
        chunks.push(result.cleanText);
        if (result.wasModified) {
            modified = true;
        }
    }
    return { cleanText: chunks.join('\n'), wasModified: modified };
}
/**
 * Recursively mask values of sensitive keys in a parsed JSON object.
 * Uses `isSensitiveKey` from the AST engine to identify keys.
 * Fixes BUG-11: Depth-limited to MAX_JSON_DEPTH to prevent stack overflow.
 * Fixes BUG-3 (partial): Also masks numeric/boolean sensitive values.
 */
function maskSensitiveJsonKeys(obj, depth = 0) {
    // Fixes BUG-11: depth guard prevents call stack overflow
    if (depth > MAX_JSON_DEPTH) {
        return false;
    }
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }
    let modified = false;
    if (Array.isArray(obj)) {
        for (const item of obj) {
            if (maskSensitiveJsonKeys(item, depth + 1)) {
                modified = true;
            }
        }
    }
    else {
        const record = obj;
        for (const key of Object.keys(record)) {
            const val = record[key];
            // Fixes BUG-3: Also mask numeric and boolean PII, not just strings
            if ((typeof val === 'string' && val.length > 0) ||
                typeof val === 'number' || typeof val === 'boolean') {
                if ((0, regexSanitizer_1.isSensitiveKey)(key)) {
                    record[key] = regexSanitizer_1.MASK;
                    modified = true;
                }
            }
            else if (typeof val === 'object' && val !== null) {
                if (maskSensitiveJsonKeys(val, depth + 1)) {
                    modified = true;
                }
            }
        }
    }
    return modified;
}
/**
 * JSON-structure-aware truncation. Slices arrays at element boundaries,
 * caps deep nesting, and injects "TRUNCATED" warning objects.
 * Fixes BUG-3: Never breaks JSON syntax.
 */
function truncateJsonStructure(obj) {
    const MAX_ARRAY_ITEMS = 50;
    let wasTruncated = false;
    function truncateNode(node, depth) {
        if (depth > MAX_JSON_DEPTH) {
            wasTruncated = true;
            return '[TRUNCATED: max depth exceeded]';
        }
        if (Array.isArray(node)) {
            if (node.length > MAX_ARRAY_ITEMS) {
                wasTruncated = true;
                const halfItems = Math.floor(MAX_ARRAY_ITEMS / 2);
                const head = node.slice(0, halfItems);
                const tail = node.slice(-halfItems);
                return [
                    ...head.map(item => truncateNode(item, depth + 1)),
                    { _safechat_truncated: `${node.length - MAX_ARRAY_ITEMS} items removed` },
                    ...tail.map(item => truncateNode(item, depth + 1)),
                ];
            }
            return node.map(item => truncateNode(item, depth + 1));
        }
        if (typeof node === 'object' && node !== null) {
            const result = {};
            for (const [key, val] of Object.entries(node)) {
                result[key] = truncateNode(val, depth + 1);
            }
            return result;
        }
        // Truncate very long string values
        if (typeof node === 'string' && node.length > 2000) {
            wasTruncated = true;
            return node.slice(0, 1000) + `... [TRUNCATED: ${node.length - 1000} chars removed]`;
        }
        return node;
    }
    const truncated = truncateNode(obj, 0);
    let result = JSON.stringify(truncated, null, 2);
    // Final byte budget enforcement
    if (Buffer.byteLength(result, 'utf-8') > MAX_PAYLOAD_BYTES) {
        result = result.slice(0, MAX_PAYLOAD_BYTES) + '\n... [TRUNCATED: exceeded byte budget]';
        wasTruncated = true;
    }
    return { text: result, wasTruncated };
}
/**
 * Structure-aware payload truncation. Preserves JSON syntax integrity.
 * Fixes BUG-3: Detects JSON and truncates at the structural level.
 * Fixes BUG-9: Enforces MAX_PAYLOAD_BYTES budget.
 */
function truncatePayloadSafely(text) {
    // If within budget, no truncation needed
    if (Buffer.byteLength(text, 'utf-8') <= MAX_PAYLOAD_BYTES) {
        return { text, wasTruncated: false };
    }
    const trimmed = text.trimStart();
    // Fixes BUG-3: JSON-aware truncation — preserve syntax
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
            const parsed = JSON.parse(text);
            return truncateJsonStructure(parsed);
        }
        catch {
            // Not valid JSON — fall through to line-based truncation
        }
    }
    // Line-based truncation for non-JSON (logs, text)
    const lines = text.split('\n');
    const maxLines = 2000;
    if (lines.length <= maxLines) {
        // Fix 1: Lines are few but each is very long — backtrack to the nearest
        // whitespace boundary so we never slice a secret token mid-character.
        // A hard slice at MAX_PAYLOAD_BYTES could cut an RSA key or AWS token in
        // half, causing the downstream regex to miss the truncated fragment.
        const hardSlice = text.slice(0, MAX_PAYLOAD_BYTES);
        const lastNewline = hardSlice.lastIndexOf('\n');
        const lastSpace = hardSlice.lastIndexOf(' ');
        // Prefer a newline boundary; fall back to a space; last resort: hard cut.
        const safeCut = lastNewline > 0 ? lastNewline
            : lastSpace > 0 ? lastSpace
                : MAX_PAYLOAD_BYTES;
        const truncated = text.slice(0, safeCut);
        return {
            text: truncated + '\n\n[... TRUNCATED: payload exceeded ' + MAX_PAYLOAD_BYTES + ' byte budget ...]',
            wasTruncated: true,
        };
    }
    const halfLines = Math.floor(maxLines / 2);
    const head = lines.slice(0, halfLines);
    const tail = lines.slice(-halfLines);
    const warningLine = `[... TRUNCATED ${lines.length - maxLines} of ${lines.length} LINES — payload exceeded ${MAX_PAYLOAD_BYTES} byte budget ...]`;
    return {
        text: [...head, warningLine, ...tail].join('\n'),
        wasTruncated: true,
    };
}
/**
 * Escapes dangerous Markdown constructs in MCP tool output to prevent
 * UI injection attacks and rendering crashes.
 * Fixes BUG-10: Prevents command-scheme links, image exfiltration,
 * and unescaped code fences from breaking the VS Code Chat UI.
 */
function escapeMcpMarkdown(text) {
    let result = text;
    // Strip command-scheme links: [text](command:anything)
    result = result.replace(/\[([^\]]*)\]\(command:[^)]*\)/gi, '[$1](blocked:command)');
    // Strip image tags that could exfiltrate data: ![alt](http(s) url)
    result = result.replace(/!\[([^\]]*)\]\(https?:[^)]*\)/gi, '[Image blocked: $1]');
    // Escape triple backticks to prevent breaking code fences
    result = result.replace(/```/g, '\\`\\`\\`');
    // Strip HTML tags that could inject content
    result = result.replace(/<(script|iframe|embed|object|form|input|link|meta)[^>]*>/gi, '[HTML blocked]');
    // Fix 4: UI Spoofing Guard — prevent MCP payloads from mimicking SafeChat
    // system alerts. An attacker-controlled MCP server (or a hallucinating LLM)
    // could emit our exact warning prefix, tricking the developer into thinking
    // a genuine SafeChat alert is being shown.
    result = result.replace(/⚠️ \*\*SafeChat/gi, '🚷 [Spoofed System Alert Blocked — SafeChat');
    // Prevent external payloads from planting our DLP marker tokens, which
    // could confuse session state lookups or fake a "safe" masked context.
    result = result.replace(/\[MASKED_BY_SAFECHAT\]/g, '[DLP_MARKER_ESCAPED]');
    return result;
}
/**
 * MCP Triage Router — sanitizes MCP tool payloads based on the routing profile
 * matched from the tool name against `safechat-rules.yaml` config.
 *
 * Fixes applied:
 *  - BUG-2:  nlp-full calls sanitizeOnly (with Presidio), not sanitizePipeline
 *  - BUG-3:  Structure-aware truncation via truncatePayloadSafely
 *  - BUG-7:  safeRegexSanitize with backtracking protection
 *  - BUG-9:  Token budget enforcement via truncation
 *  - BUG-11: Depth-limited maskSensitiveJsonKeys
 *  - BUG-14: Sequential batching eliminates shared regex state
 */
async function sanitizeMcpPayload(text, toolName, config) {
    const profile = matchMcpProfile(toolName, config);
    console.log(`[SafeChat] MCP Router: tool="${toolName}" → profile="${profile}"`);
    ensureHydrated(config);
    // ── bypass ────────────────────────────────────────────────────────────
    if (profile === 'bypass') {
        return { cleanText: text, wasModified: false };
    }
    // ── Step 0: Enforce byte budget before any processing (BUG-9) ─────────
    let { text: payload, wasTruncated } = truncatePayloadSafely(text);
    // ── json-keys ─────────────────────────────────────────────────────────
    if (profile === 'json-keys') {
        try {
            const parsed = JSON.parse(payload);
            // Fixes BUG-11: depth-limited masking
            const wasModified = maskSensitiveJsonKeys(parsed, 0);
            const result = JSON.stringify(parsed, null, 2);
            // Fixes BUG-3: Re-check byte budget after re-serialization
            if (Buffer.byteLength(result, 'utf-8') > MAX_PAYLOAD_BYTES) {
                const { text: truncResult } = truncatePayloadSafely(result);
                return { cleanText: truncResult, wasModified: wasModified || wasTruncated };
            }
            return { cleanText: result, wasModified: wasModified || wasTruncated };
        }
        catch {
            // Fixes BUG-3: JSON parse failed — apply regex to WHOLE string, do NOT line-split
            console.log(`[SafeChat] MCP json-keys: JSON.parse failed for ${toolName}, applying regex to whole payload`);
            const result = safeRegexSanitize(payload);
            return { cleanText: result.cleanText, wasModified: result.wasModified || wasTruncated };
        }
    }
    // ── nlp-full — Fixes BUG-2: Use sanitizeOnly which calls Presidio ────
    if (profile === 'nlp-full') {
        const result = await sanitizeOnly(payload, config);
        return {
            cleanText: result.cleanText,
            wasModified: result.wasModified || wasTruncated,
            presidioError: result.presidioError, // Fixes BUG-4: surface errors
        };
    }
    // ── regex-only (Sequential Line-Batching) ─────────────────────────────
    const lines = payload.split('\n');
    // Fixes BUG-14: Sequential batching — process one batch at a time
    // to eliminate shared RegExp .lastIndex state race conditions
    const BATCH_SIZE = 500;
    let wasModified = wasTruncated;
    const sanitizedBatches = [];
    for (let i = 0; i < lines.length; i += BATCH_SIZE) {
        const batch = lines.slice(i, i + BATCH_SIZE).join('\n');
        // Fixes BUG-7: safeRegexSanitize handles backtracking-prone patterns
        const result = safeRegexSanitize(batch);
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