"use strict";
/**
 * router.ts — Central Routing Controller
 * ═══════════════════════════════════════
 * Routes tool outputs through the appropriate sanitization pipeline:
 * - Source code → bypass (no scanning)
 * - Flat files (.env, .ini, .properties) → Gitleaks raw scan
 * - Structured files (JSON, YAML, TOML) → Gitleaks raw scan + Tree-Sitter verification
 * - XML → Gitleaks raw scan (no WASM grammar available)
 * - Terminal / MCP / unknown → heuristic-based Gitleaks scan
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MASK = void 0;
exports.updateConfig = updateConfig;
exports.initRouter = initRouter;
exports.routeAndSanitize = routeAndSanitize;
const gitleaksEngine_1 = require("./gitleaksEngine");
const treeSitterEngine_1 = require("./treeSitterEngine");
const heuristic_1 = require("./heuristic");
// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────
exports.MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000; // 250 KB
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
const DEFAULT_CST_XML = ['.xml', '.xsl', '.xslt', '.svg', '.plist'];
const DEFAULT_FLAT = [
    '.env', '.ini', '.cfg', '.properties',
    '.pgpass', '.netrc', '.npmrc',
    '.env.local', '.env.production', '.env.development',
    '.sh', '.bash', '.zsh', '.fish',
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
let CST_XML_EXTENSIONS = new Set();
let FLAT_EXTENSIONS = new Set();
function resetToDefaults() {
    BYPASS_EXTENSIONS = new Set(DEFAULT_BYPASS);
    CST_JSON_EXTENSIONS = new Set(DEFAULT_CST_JSON);
    CST_YAML_EXTENSIONS = new Set(DEFAULT_CST_YAML);
    CST_TOML_EXTENSIONS = new Set(DEFAULT_CST_TOML);
    CST_XML_EXTENSIONS = new Set(DEFAULT_CST_XML);
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
        if (Array.isArray(config.routing.cst_xml)) {
            CST_XML_EXTENSIONS = new Set(config.routing.cst_xml);
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
 *   2. Flat files (.env, .ini, .properties, .pgpass) → Gitleaks raw scan
 *   3. Structured files with CST grammar (JSON, YAML, TOML) → Tree-Sitter + Gitleaks
 *   4. XML files → Gitleaks raw scan (no WASM grammar)
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
    const strictConfigPath = (0, heuristic_1.getConfigPath)('strict', cachedExtensionPath);
    // ── RULE 2: Flat Files → Gitleaks Raw Scan ─────────────────────────
    if (FLAT_EXTENSIONS.has(ext)) {
        return gitleaksRawScan(text, strictConfigPath, `flat:${ext}`, redactions);
    }
    // ── RULE 3: Structured Files with CST Grammar ──────────────────────
    const cstLang = getCSTLang(ext);
    if (cstLang) {
        return cstPipeline(text, cstLang, strictConfigPath, `cst:${cstLang}`, redactions);
    }
    // ── RULE 4: XML Files → Gitleaks Raw Scan (no WASM) ────────────────
    if (CST_XML_EXTENSIONS.has(ext)) {
        return gitleaksRawScan(text, strictConfigPath, `gitleaks:xml`, redactions);
    }
    // ── RULE 5: Terminal / MCP / Catch-All ─────────────────────────────
    // Try to detect structured content in MCP/terminal output
    if (!ext || ext === '.') {
        const detected = detectContentType(text);
        const detectedLang = detectedTypeToCSTLang(detected);
        if (detectedLang) {
            return cstPipeline(text, detectedLang, strictConfigPath, `cst:${detectedLang}:detected`, redactions);
        }
        if (detected === 'xml') {
            return gitleaksRawScan(text, strictConfigPath, 'gitleaks:xml:detected', redactions);
        }
        if (detected === 'flat') {
            return gitleaksRawScan(text, strictConfigPath, 'gitleaks:flat:detected', redactions);
        }
    }
    // Unstructured text — use heuristic to pick config
    const command = toolContext?.command ?? extractCommandFromInput(toolContext?.toolInput);
    const mode = (0, heuristic_1.classifyTerminalMode)(command, text);
    const configPath = (0, heuristic_1.getConfigPath)(mode, cachedExtensionPath);
    // Apply truncation guard for large payloads
    const { text: truncated, wasTruncated } = truncateIfNeeded(text, redactions);
    return gitleaksRawScan(truncated, configPath, `gitleaks:${mode}`, redactions, wasTruncated);
}
// ────────────────────────────────────────────────────────────────────────────
// Pipeline Helpers
// ────────────────────────────────────────────────────────────────────────────
async function cstPipeline(text, lang, configPath, route, redactions) {
    try {
        // Pass 1: Gitleaks scans the FULL raw text (all context preserved)
        const findings = await (0, gitleaksEngine_1.scanWithGitleaks)(text, configPath, cachedBinaryPath);
        if (findings.length === 0) {
            return { cleanText: text, wasModified: false, route, redactions };
        }
        // Pass 2: Tree-Sitter verifies each finding is inside a value node
        const verified = await (0, treeSitterEngine_1.verifyFindings)(text, lang, findings);
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
async function gitleaksRawScan(text, configPath, route, redactions, alreadyTruncated = false) {
    // Apply truncation guard if not already done
    let current = text;
    let wasTruncated = alreadyTruncated;
    if (!alreadyTruncated) {
        const trunc = truncateIfNeeded(text, redactions);
        current = trunc.text;
        wasTruncated = trunc.wasTruncated;
    }
    try {
        const findings = await (0, gitleaksEngine_1.scanWithGitleaks)(current, configPath, cachedBinaryPath);
        const result = (0, gitleaksEngine_1.applyMask)(current, findings, exports.MASK);
        redactions.push(...result.redactions);
        return {
            cleanText: result.cleanText,
            wasModified: result.wasModified || wasTruncated,
            route,
            redactions,
        };
    }
    catch (err) {
        console.error(`[SafeChat] Gitleaks scan failed for route ${route}:`, err);
        // Fail-closed: return text unchanged but log the error
        return {
            cleanText: current,
            wasModified: wasTruncated,
            route: `error:${route}`,
            redactions,
        };
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