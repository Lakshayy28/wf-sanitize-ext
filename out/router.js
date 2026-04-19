"use strict";
/**
 * router.ts — Central Routing Controller
 * ═══════════════════════════════════════
 * Routes tool outputs through the appropriate sanitization pipeline:
 * - Source code → bypass (no scanning)
 * - Flat files (.properties, .pgpass, .sql, etc.) → Gitleaks raw scan
 * - Structured files (JSON, YAML, TOML, XML, ENV, INI) → Gitleaks + Tree-Sitter CST verification
 * - JSONL/NDJSON → Gitleaks + per-line JSON CST verification
 * - Terminal / MCP / unknown → heuristic-based Gitleaks scan
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MASK = void 0;
exports.updateConfig = updateConfig;
exports.setUserConfigPath = setUserConfigPath;
exports.initRouter = initRouter;
exports.routeAndSanitize = routeAndSanitize;
const gitleaksEngine_1 = require("./gitleaksEngine");
const treeSitterEngine_1 = require("./treeSitterEngine");
const heuristic_1 = require("./heuristic");
// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────
exports.MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000; // 250 KB truncation threshold
const MAX_SCAN_BYTES = 2_000_000; // 2 MB hard cap — reject before scanning
// ────────────────────────────────────────────────────────────────────────────
// Extension Set Defaults
// ────────────────────────────────────────────────────────────────────────────
const DEFAULT_BYPASS = [
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.py', '.pyw',
    '.java', '.kt', '.kts', '.scala',
    '.go',
    '.rs',
    '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx',
    '.cs',
    '.rb',
    '.php',
    '.swift',
    '.m', '.mm',
    '.dart',
    '.lua',
    '.r', '.R',
    '.pl', '.pm',
    '.vue', '.svelte',
    '.proto',
    '.graphql', '.gql',
];
const DEFAULT_CST_JSON = ['.json', '.jsonc', '.json5'];
const DEFAULT_CST_YAML = ['.yaml', '.yml'];
const DEFAULT_CST_TOML = ['.toml'];
const DEFAULT_CST_HTML = ['.xml', '.xsl', '.xslt', '.svg', '.plist'];
const DEFAULT_CST_BASH = ['.env', '.sh', '.bash', '.zsh', '.fish'];
const DEFAULT_CST_INI = ['.ini', '.cfg'];
const DEFAULT_FLAT = [
    '.properties',
    '.pgpass', '.netrc', '.npmrc',
    '.ps1', '.psm1',
    '.sql',
    '.tf', '.hcl',
];
// ────────────────────────────────────────────────────────────────────────────
// Mutable Configuration State
// ────────────────────────────────────────────────────────────────────────────
let BYPASS_EXTENSIONS = new Set();
let CST_JSON_EXTENSIONS = new Set();
let CST_YAML_EXTENSIONS = new Set();
let CST_TOML_EXTENSIONS = new Set();
let CST_HTML_EXTENSIONS = new Set();
let CST_BASH_EXTENSIONS = new Set();
let CST_INI_EXTENSIONS = new Set();
let FLAT_EXTENSIONS = new Set();
function resetToDefaults() {
    BYPASS_EXTENSIONS = new Set(DEFAULT_BYPASS);
    CST_JSON_EXTENSIONS = new Set(DEFAULT_CST_JSON);
    CST_YAML_EXTENSIONS = new Set(DEFAULT_CST_YAML);
    CST_TOML_EXTENSIONS = new Set(DEFAULT_CST_TOML);
    CST_HTML_EXTENSIONS = new Set(DEFAULT_CST_HTML);
    CST_BASH_EXTENSIONS = new Set(DEFAULT_CST_BASH);
    CST_INI_EXTENSIONS = new Set(DEFAULT_CST_INI);
    FLAT_EXTENSIONS = new Set(DEFAULT_FLAT);
}
resetToDefaults();
function updateConfig(config) {
    if (!config) {
        console.log('[SafeChat] Config absent or removed. Resetting to defaults.');
        resetToDefaults();
        return;
    }
    if (config.routing) {
        if (Array.isArray(config.routing.bypass)) {
            BYPASS_EXTENSIONS = new Set(config.routing.bypass);
        }
        if (Array.isArray(config.routing.cst_json)) {
            CST_JSON_EXTENSIONS = new Set(config.routing.cst_json);
        }
        if (Array.isArray(config.routing.cst_yaml)) {
            CST_YAML_EXTENSIONS = new Set(config.routing.cst_yaml);
        }
        if (Array.isArray(config.routing.cst_toml)) {
            CST_TOML_EXTENSIONS = new Set(config.routing.cst_toml);
        }
        if (Array.isArray(config.routing.cst_html)) {
            CST_HTML_EXTENSIONS = new Set(config.routing.cst_html);
        }
        if (Array.isArray(config.routing.cst_bash)) {
            CST_BASH_EXTENSIONS = new Set(config.routing.cst_bash);
        }
        if (Array.isArray(config.routing.cst_ini)) {
            CST_INI_EXTENSIONS = new Set(config.routing.cst_ini);
        }
        if (Array.isArray(config.routing.flat)) {
            FLAT_EXTENSIONS = new Set(config.routing.flat);
        }
    }
    else {
        resetToDefaults();
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Extension Path Cache (set during init)
// ────────────────────────────────────────────────────────────────────────────
let cachedExtensionPath = '';
let cachedBinaryPath = '';
let cachedUserConfigPath = '';
/** Called by extension.ts when the user drops/updates safechat-rules.toml in the workspace root. */
function setUserConfigPath(p) {
    cachedUserConfigPath = p;
    console.log(`[SafeChat] User Gitleaks config ${p ? `loaded: ${p}` : 'cleared — using bundled strict.toml'}`);
}
/**
 * Initialize the router. Must be called once during extension activation.
 * Sets up Tree-Sitter runtime and resolves Gitleaks binary path.
 */
async function initRouter(extensionPath) {
    cachedExtensionPath = extensionPath;
    cachedBinaryPath = (0, gitleaksEngine_1.getGitleaksBinary)(extensionPath);
    // Initialize Tree-Sitter WASM runtime
    await (0, treeSitterEngine_1.initTreeSitter)(extensionPath);
}
/**
 * Attempt to detect the content type of untyped text (MCP output, etc.).
 * Uses trial parsing and heuristic patterns.
 */
function detectContentType(text) {
    const trimmed = text.trimStart();
    // JSON: starts with { or [
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
            JSON.parse(text);
            return 'json';
        }
        catch {
            // Not valid JSON; might still be structured
        }
    }
    // XML: starts with < (but not HTML script/style)
    if (trimmed.startsWith('<') && !trimmed.startsWith('<!DOCTYPE html') && !trimmed.startsWith('<html')) {
        if (/<\/?[a-zA-Z][\w.-]*[^>]*>/.test(trimmed)) {
            return 'xml';
        }
    }
    // YAML: starts with --- or has key: value patterns
    if (trimmed.startsWith('---') || /^[a-zA-Z_][\w.-]*\s*:/m.test(trimmed)) {
        // Verify with multiple key: value lines
        const keyValueLines = trimmed.split('\n').filter(l => /^[a-zA-Z_][\w.-]*\s*:/.test(l.trim()));
        if (keyValueLines.length >= 2) {
            return 'yaml';
        }
    }
    // TOML: has [section] headers and key = value patterns
    if (/^\s*\[[a-zA-Z][\w.-]*\]/m.test(trimmed) && /^[a-zA-Z_][\w.-]*\s*=/m.test(trimmed)) {
        return 'toml';
    }
    // Flat key=value: multiple lines with KEY=VALUE or KEY = VALUE
    const kvLines = trimmed.split('\n').filter(l => /^[A-Za-z_][\w.-]*\s*=/.test(l.trim()));
    if (kvLines.length >= 2) {
        return 'flat';
    }
    return 'raw';
}
// ────────────────────────────────────────────────────────────────────────────
// Truncation Guard
// ────────────────────────────────────────────────────────────────────────────
function truncateIfNeeded(text, redactions) {
    const byteLen = Buffer.byteLength(text, 'utf-8');
    if (byteLen <= MAX_BUDGET_BYTES) {
        return { text, wasTruncated: false };
    }
    const buf = Buffer.from(text, 'utf-8');
    const sliced = buf.subarray(0, MAX_BUDGET_BYTES).toString('utf-8');
    const lastNl = sliced.lastIndexOf('\n');
    const safeCut = lastNl > 0 ? lastNl : sliced.length;
    const truncated = sliced.slice(0, safeCut) +
        '\n\n[... TRUNCATED: payload exceeded 250KB budget ...]';
    redactions.push('Payload Truncation (>250KB)');
    return { text: truncated, wasTruncated: true };
}
// ────────────────────────────────────────────────────────────────────────────
// CST Language Mapping
// ────────────────────────────────────────────────────────────────────────────
function getCSTLang(ext) {
    if (CST_JSON_EXTENSIONS.has(ext)) {
        return 'json';
    }
    if (CST_YAML_EXTENSIONS.has(ext)) {
        return 'yaml';
    }
    if (CST_TOML_EXTENSIONS.has(ext)) {
        return 'toml';
    }
    if (CST_HTML_EXTENSIONS.has(ext)) {
        return 'html';
    }
    if (CST_BASH_EXTENSIONS.has(ext)) {
        return 'bash';
    }
    if (CST_INI_EXTENSIONS.has(ext)) {
        return 'ini';
    }
    return null;
}
function detectedTypeToCSTLang(detected) {
    if (detected === 'json') {
        return 'json';
    }
    if (detected === 'yaml') {
        return 'yaml';
    }
    if (detected === 'toml') {
        return 'toml';
    }
    if (detected === 'xml') {
        return 'html';
    }
    return null;
}
// ────────────────────────────────────────────────────────────────────────────
// The Central Router (public entry point)
// ────────────────────────────────────────────────────────────────────────────
/**
 * Route tool output through the appropriate sanitization pipeline.
 *
 * Rules (evaluated in order):
 *   0. Tool error bypass — pass through
 *   1. Source code bypass — pass through
 *   2. Flat files (.properties, .pgpass, etc.) → Gitleaks raw scan
 *   3. Structured files with CST grammar (JSON, YAML, TOML, XML, Bash/ENV, INI) → Tree-Sitter + Gitleaks
 *   4. JSONL/NDJSON → per-line JSON CST pipeline
 *   5. Terminal / MCP / catch-all → heuristic + Gitleaks raw scan
 */
async function routeAndSanitize(text, fileExtension, toolContext) {
    const redactions = [];
    // ── RULE 0: Tool Error Bypass ──────────────────────────────────────
    if (text.startsWith('Error invoking tool')) {
        return { cleanText: text, wasModified: false, route: 'bypass:tool-error', redactions };
    }
    const ext = (fileExtension ?? '').toLowerCase().replace(/^\.?/, '.');
    // ── RULE 1: Source Code Bypass ─────────────────────────────────────
    if (BYPASS_EXTENSIONS.has(ext)) {
        return { cleanText: text, wasModified: false, route: 'bypass:code', redactions };
    }
    const strictConfigPath = cachedUserConfigPath || (0, heuristic_1.getConfigPath)('strict', cachedExtensionPath);
    // ── RULE 2: Flat Files → Gitleaks Raw Scan ─────────────────────────
    if (FLAT_EXTENSIONS.has(ext)) {
        return gitleaksRawScan(text, strictConfigPath, `flat:${ext}`, redactions);
    }
    // ── RULE 3: Structured Files with CST Grammar ──────────────────────
    const cstLang = getCSTLang(ext);
    if (cstLang) {
        return cstPipeline(text, cstLang, strictConfigPath, `cst:${cstLang}`, redactions);
    }
    // ── RULE 4: JSONL / NDJSON → per-line JSON CST pipeline ────────────
    if (ext === '.jsonl' || ext === '.ndjson') {
        return jsonlPipeline(text, strictConfigPath, `cst:json:jsonl`, redactions);
    }
    // ── RULE 5: Terminal / MCP / Catch-All ─────────────────────────────
    // Try to detect structured content in MCP/terminal output
    if (!ext || ext === '.') {
        const detected = detectContentType(text);
        const detectedLang = detectedTypeToCSTLang(detected);
        if (detectedLang) {
            return cstPipeline(text, detectedLang, strictConfigPath, `cst:${detectedLang}:detected`, redactions);
        }
        if (detected === 'flat') {
            return gitleaksRawScan(text, strictConfigPath, 'gitleaks:flat:detected', redactions);
        }
    }
    // Unstructured text — use heuristic to pick config
    const command = toolContext?.command ?? extractCommandFromInput(toolContext?.toolInput);
    const mode = (0, heuristic_1.classifyTerminalMode)(command, text);
    const configPath = (0, heuristic_1.getConfigPath)(mode, cachedExtensionPath);
    return gitleaksRawScan(text, configPath, `gitleaks:${mode}`, redactions);
}
// ────────────────────────────────────────────────────────────────────────────
// Pipeline Helpers
// ────────────────────────────────────────────────────────────────────────────
async function cstPipeline(text, lang, configPath, route, redactions) {
    try {
        // Parallel: Gitleaks scan + Tree-Sitter parse run simultaneously
        const [findings, tree] = await Promise.all([
            (0, gitleaksEngine_1.scanWithGitleaks)(text, configPath, cachedBinaryPath),
            lang !== 'ini' ? (0, treeSitterEngine_1.parseCST)(text, lang) : Promise.resolve(null),
        ]);
        if (findings.length === 0) {
            if (tree) {
                tree.delete();
            }
            return { cleanText: text, wasModified: false, route, redactions };
        }
        // Verify findings against CST (uses pre-parsed tree when available)
        const verified = await (0, treeSitterEngine_1.verifyFindings)(text, lang, findings, tree);
        if (tree) {
            tree.delete();
        }
        if (verified.length === 0) {
            return { cleanText: text, wasModified: false, route, redactions };
        }
        // Mask only verified findings
        const result = (0, gitleaksEngine_1.applyMask)(text, verified, exports.MASK);
        redactions.push(...result.redactions);
        return {
            cleanText: result.cleanText,
            wasModified: result.wasModified,
            route,
            redactions,
        };
    }
    catch (err) {
        console.warn(`[SafeChat] CST pipeline failed for ${route}, falling back to raw scan:`, err);
        return gitleaksRawScan(text, configPath, `fallback:${route}`, redactions);
    }
}
async function gitleaksRawScan(text, configPath, route, redactions) {
    // 2 MB hard cap — reject oversized payloads before scanning
    const byteLen = Buffer.byteLength(text, 'utf-8');
    if (byteLen > MAX_SCAN_BYTES) {
        redactions.push('Payload Rejected (>2MB)');
        return {
            cleanText: '[SafeChat] Payload too large to scan (>2MB). Content blocked.',
            wasModified: true,
            route: `rejected:${route}`,
            redactions,
        };
    }
    try {
        // Scan the FULL text first (scan-then-truncate: no secrets escape via truncation)
        const findings = await (0, gitleaksEngine_1.scanWithGitleaks)(text, configPath, cachedBinaryPath);
        const result = (0, gitleaksEngine_1.applyMask)(text, findings, exports.MASK);
        redactions.push(...result.redactions);
        // THEN truncate the masked output if needed
        const { text: truncated, wasTruncated } = truncateIfNeeded(result.cleanText, redactions);
        return {
            cleanText: truncated,
            wasModified: result.wasModified || wasTruncated,
            route,
            redactions,
        };
    }
    catch (err) {
        console.error(`[SafeChat] Gitleaks scan failed for route ${route}:`, err);
        return {
            cleanText: text,
            wasModified: false,
            route: `error:${route}`,
            redactions,
        };
    }
}
/**
 * JSONL/NDJSON pipeline: scans full text with Gitleaks once,
 * then verifies findings per-line using JSON CST.
 */
async function jsonlPipeline(text, configPath, route, redactions) {
    try {
        const findings = await (0, gitleaksEngine_1.scanWithGitleaks)(text, configPath, cachedBinaryPath);
        if (findings.length === 0) {
            return { cleanText: text, wasModified: false, route, redactions };
        }
        const verified = await (0, treeSitterEngine_1.verifyJsonlFindings)(text, findings);
        if (verified.length === 0) {
            return { cleanText: text, wasModified: false, route, redactions };
        }
        const result = (0, gitleaksEngine_1.applyMask)(text, verified, exports.MASK);
        redactions.push(...result.redactions);
        return {
            cleanText: result.cleanText,
            wasModified: result.wasModified,
            route,
            redactions,
        };
    }
    catch (err) {
        console.warn(`[SafeChat] JSONL pipeline failed, falling back to raw scan:`, err);
        return gitleaksRawScan(text, configPath, `fallback:${route}`, redactions);
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Utility
// ────────────────────────────────────────────────────────────────────────────
/**
 * Extract a command string from tool input for heuristic classification.
 */
function extractCommandFromInput(input) {
    if (!input || typeof input !== 'object') {
        return undefined;
    }
    const record = input;
    if (typeof record['command'] === 'string') {
        return record['command'];
    }
    if (typeof record['cmd'] === 'string') {
        return record['cmd'];
    }
    return undefined;
}
//# sourceMappingURL=router.js.map