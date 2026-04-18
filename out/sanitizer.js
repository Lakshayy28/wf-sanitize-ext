"use strict";
/**
 * sanitizer.ts — Smart Proxy: Polyglot AST Router + Regex DLP Engine
 * ════════════════════════════════════════════════════════════════════
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
exports.HIGH_CONFIDENCE_SECRETS = exports.MASK = void 0;
exports.updateConfig = updateConfig;
exports.regexSanitize = regexSanitize;
exports.calculateEntropy = calculateEntropy;
exports.maskObjectValues = maskObjectValues;
exports.truncateAndSanitize = truncateAndSanitize;
exports.smartSanitize = smartSanitize;
const yaml = __importStar(require("yaml"));
const fast_xml_parser_1 = require("fast-xml-parser");
// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────
exports.MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000; // 250 KB
const IS_DEV_MODE = true;
function logRedaction(patternName, matchedSecret) {
    if (IS_DEV_MODE) {
        console.warn(`[SafeChat DEBUG] Redacted ${patternName}: "${matchedSecret}"`);
    }
    else {
        console.info(`[SafeChat AUDIT] Redacted ${patternName} (length: ${matchedSecret.length})`);
    }
}
exports.HIGH_CONFIDENCE_SECRETS = [
    { name: 'AWS Access Key', regex: /\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}\b/g },
    { name: 'Stripe Key', regex: /\b([spr]k_(?:live|test)_[A-Za-z0-9]{24,99})\b/g },
    { name: 'Slack Token', regex: /\b(xox[bpas]-[0-9A-Za-z\-]+)\b/g },
    { name: 'GitHub Token', regex: /\b(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/g },
    { name: 'IPv4 Address', regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g },
    { name: 'Email Address', regex: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
    { name: 'Credit Card Number', regex: /\b(?!(?:9007199254740991))(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b/g },
    { name: 'URI Password', regex: /(?:\w+:\/\/)[^:\s@]+:([^:@\s]{6,})@/g },
    { name: 'Connection String Password', regex: /(?:password|pwd|secret)\s*=\s*([^;'"\s\\]{6,})/gi },
    { name: 'Pgpass Password', regex: /^(?:[^:\r\n]+:){4}([^:\r\n]+)$/gm },
];
// ────────────────────────────────────────────────────────────────────────────
// Configuration Management (`safechat.yml` dynamic routing)
// ────────────────────────────────────────────────────────────────────────────
let BYPASS_EXTENSIONS = new Set();
let AST_JSON_EXTENSIONS = new Set();
let AST_YAML_EXTENSIONS = new Set();
let AST_XML_EXTENSIONS = new Set();
let AST_ENV_EXTENSIONS = new Set();
let DYNAMIC_PATTERNS = [];
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
    '.sh', '.bash', '.zsh', '.fish',
    '.ps1', '.psm1',
    '.sql',
    '.vue', '.svelte',
    '.tf', '.hcl',
    '.proto',
    '.graphql', '.gql',
];
const DEFAULT_AST_JSON = ['.json', '.jsonc', '.json5'];
const DEFAULT_AST_YAML = ['.yaml', '.yml'];
const DEFAULT_AST_XML = ['.xml', '.xsl', '.xslt', '.svg', '.plist'];
const DEFAULT_AST_ENV = ['.env', '.ini', '.cfg', '.properties', '.env.local', '.env.production', '.env.development'];
function resetToDefaults() {
    BYPASS_EXTENSIONS = new Set(DEFAULT_BYPASS);
    AST_JSON_EXTENSIONS = new Set(DEFAULT_AST_JSON);
    AST_YAML_EXTENSIONS = new Set(DEFAULT_AST_YAML);
    AST_XML_EXTENSIONS = new Set(DEFAULT_AST_XML);
    AST_ENV_EXTENSIONS = new Set(DEFAULT_AST_ENV);
    DYNAMIC_PATTERNS = [];
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
        if (Array.isArray(config.routing.ast_json)) {
            AST_JSON_EXTENSIONS = new Set(config.routing.ast_json);
        }
        if (Array.isArray(config.routing.ast_yaml)) {
            AST_YAML_EXTENSIONS = new Set(config.routing.ast_yaml);
        }
        if (Array.isArray(config.routing.ast_xml)) {
            AST_XML_EXTENSIONS = new Set(config.routing.ast_xml);
        }
        if (Array.isArray(config.routing.ast_env)) {
            AST_ENV_EXTENSIONS = new Set(config.routing.ast_env);
        }
    }
    else {
        resetToDefaults();
    }
    DYNAMIC_PATTERNS = [];
    if (Array.isArray(config.custom_patterns)) {
        for (const pat of config.custom_patterns) {
            if (pat.name && pat.regex) {
                try {
                    let r = new RegExp(pat.regex, 'g');
                    DYNAMIC_PATTERNS.push({ name: pat.name, regex: r });
                }
                catch (err) {
                    console.warn(`[SafeChat] Failed to compile regex for custom pattern "${pat.name}":`, err);
                }
            }
        }
    }
}
// ────────────────────────────────────────────────────────────────────────────
// Tier 1: Pure Regex Sanitizer
// ────────────────────────────────────────────────────────────────────────────
function regexSanitize(text, redactions = []) {
    let wasModified = false;
    let current = text;
    const allPatterns = [...exports.HIGH_CONFIDENCE_SECRETS, ...DYNAMIC_PATTERNS];
    for (const pattern of allPatterns) {
        pattern.regex.lastIndex = 0;
        if (pattern.isUrlAuth) {
            const replaced = current.replace(pattern.regex, (_full, proto, _auth, host) => {
                wasModified = true;
                logRedaction(pattern.name, _auth);
                redactions.push(pattern.name);
                return `${proto}${exports.MASK}${host}`;
            });
            if (replaced !== current) {
                current = replaced;
            }
        }
        else {
            const replaced = current.replace(pattern.regex, (full, captured) => {
                wasModified = true;
                const secretValue = captured !== undefined ? captured : full;
                logRedaction(pattern.name, secretValue);
                redactions.push(pattern.name);
                if (captured !== undefined) {
                    return full.replace(captured, exports.MASK);
                }
                return exports.MASK;
            });
            if (replaced !== current) {
                current = replaced;
            }
        }
    }
    // THE FIX: Removed '=' from the core character class to stop swallowing KEY=VALUE statements.
    // Added (?:={1,2})? at the end to gracefully support Base64 padding without breaking config lines.
    const genericTokenRegex = /([A-Za-z0-9+/_\-@!#$%^&*?]{16,}(?:={1,2})?)/g;
    const replacedWithEntropy = current.replace(genericTokenRegex, (match, p1, offset, originalString) => {
        if (hasSecretContext(originalString, offset)) {
            wasModified = true;
            logRedaction('Anchored Secret', match);
            redactions.push('Anchored Secret');
            return exports.MASK;
        }
        const entropy = calculateEntropy(match);
        if (entropy > 4.5) {
            wasModified = true;
            logRedaction('High Entropy Token', match);
            redactions.push('High Entropy Token');
            return exports.MASK;
        }
        return match;
    });
    if (replacedWithEntropy !== current) {
        current = replacedWithEntropy;
    }
    return { cleanText: current, wasModified };
}
function hasSecretContext(text, matchIndex) {
    const prefix = text.substring(Math.max(0, matchIndex - 40), matchIndex).toLowerCase();
    const anchorRegex = /secret|token|key|password|passwd|pwd|api|cred|auth|cert|signature/i;
    const assignmentRegex = /[:=]\s*["']?$/;
    return anchorRegex.test(prefix) || assignmentRegex.test(prefix);
}
function calculateEntropy(str) {
    if (!str) {
        return 0;
    }
    const len = str.length;
    const frequencies = new Map();
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of frequencies.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
// ────────────────────────────────────────────────────────────────────────────
// Tier 2: Universal Object Masker (recursive AST walker)
// ────────────────────────────────────────────────────────────────────────────
const MAX_DEPTH = 64;
const SENSITIVE_KEY_HEURISTIC = /secret|password|passwd|pwd|token|key|api|cred|auth|cert/i;
function maskObjectValues(obj, depth = 0, currentKey, redactions = []) {
    if (depth > MAX_DEPTH) {
        return { masked: obj, wasModified: false };
    }
    if (obj === null || obj === undefined) {
        return { masked: obj, wasModified: false };
    }
    if (typeof obj === 'string') {
        if (currentKey && SENSITIVE_KEY_HEURISTIC.test(currentKey)) {
            if (obj.length > 0 && obj !== exports.MASK) {
                redactions.push('Key Heuristic Match');
                return { masked: exports.MASK, wasModified: true };
            }
            return { masked: obj, wasModified: false };
        }
        const { cleanText, wasModified } = regexSanitize(obj, redactions);
        return { masked: cleanText, wasModified };
    }
    if (typeof obj !== 'object') {
        return { masked: obj, wasModified: false };
    }
    if (Array.isArray(obj)) {
        let anyModified = false;
        const maskedArr = obj.map(item => {
            const { masked, wasModified } = maskObjectValues(item, depth + 1, undefined, redactions);
            if (wasModified) {
                anyModified = true;
            }
            return masked;
        });
        return { masked: maskedArr, wasModified: anyModified };
    }
    let anyModified = false;
    const maskedObj = {};
    for (const [k, value] of Object.entries(obj)) {
        const { masked, wasModified } = maskObjectValues(value, depth + 1, k, redactions);
        maskedObj[k] = masked;
        if (wasModified) {
            anyModified = true;
        }
    }
    return { masked: maskedObj, wasModified: anyModified };
}
// ────────────────────────────────────────────────────────────────────────────
// Truncation + Regex Fallback
// ────────────────────────────────────────────────────────────────────────────
function truncateAndSanitize(text, redactions = []) {
    let current = text;
    let wasTruncated = false;
    const byteLen = Buffer.byteLength(current, 'utf-8');
    if (byteLen > MAX_BUDGET_BYTES) {
        const buf = Buffer.from(current, 'utf-8');
        const sliced = buf.subarray(0, MAX_BUDGET_BYTES).toString('utf-8');
        const lastNl = sliced.lastIndexOf('\n');
        const safeCut = lastNl > 0 ? lastNl : sliced.length;
        current = sliced.slice(0, safeCut) +
            '\n\n[... TRUNCATED: payload exceeded 250KB budget ...]';
        wasTruncated = true;
        redactions.push('Payload Truncation (>250KB)');
    }
    const { cleanText, wasModified } = regexSanitize(current, redactions);
    return { cleanText, wasModified: wasModified || wasTruncated };
}
// ────────────────────────────────────────────────────────────────────────────
// ENV / INI line-by-line parser
// ────────────────────────────────────────────────────────────────────────────
function sanitizeEnvText(text, redactions = []) {
    let wasModified = false;
    const lines = text.split('\n');
    const sanitizedLines = lines.map(line => {
        const trimmed = line.trim();
        if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) {
            return line;
        }
        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) {
            const { cleanText, wasModified: lm } = regexSanitize(line, redactions);
            if (lm) {
                wasModified = true;
            }
            return cleanText;
        }
        const key = line.slice(0, eqIdx);
        let value = line.slice(eqIdx + 1);
        let quote = '';
        const trimVal = value.trim();
        if ((trimVal.startsWith('"') && trimVal.endsWith('"')) ||
            (trimVal.startsWith("'") && trimVal.endsWith("'"))) {
            quote = trimVal[0];
            value = trimVal.slice(1, -1);
        }
        if (SENSITIVE_KEY_HEURISTIC.test(key.trim())) {
            if (value.length > 0 && value !== exports.MASK) {
                redactions.push('ENV Key Heuristic Match');
                wasModified = true;
                return quote ? `${key}=${quote}${exports.MASK}${quote}` : `${key}=${exports.MASK}`;
            }
            return quote ? `${key}=${quote}${value}${quote}` : `${key}=${value}`;
        }
        const { cleanText: maskedVal, wasModified: vm } = regexSanitize(value, redactions);
        if (vm) {
            wasModified = true;
        }
        return quote ? `${key}=${quote}${maskedVal}${quote}` : `${key}=${maskedVal}`;
    });
    return { cleanText: sanitizedLines.join('\n'), wasModified };
}
const XML_PARSER_OPTS = {
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    preserveOrder: false,
    trimValues: false,
};
// ────────────────────────────────────────────────────────────────────────────
// The Smart Router (public entry point)
// ────────────────────────────────────────────────────────────────────────────
function smartSanitize(text, fileExtension, logFn = () => { }) {
    const redactions = [];
    if (text.startsWith('Error invoking tool')) {
        return { cleanText: text, wasModified: false, route: 'bypass:tool-error', redactions };
    }
    const ext = (fileExtension ?? '').toLowerCase().replace(/^\.?/, '.');
    if (BYPASS_EXTENSIONS.has(ext)) {
        return { cleanText: text, wasModified: false, route: 'bypass:code', redactions };
    }
    if (AST_JSON_EXTENSIONS.has(ext)) {
        try {
            const parsed = JSON.parse(text);
            const { masked, wasModified } = maskObjectValues(parsed, 0, undefined, redactions);
            return {
                cleanText: JSON.stringify(masked, null, 2),
                wasModified,
                route: 'ast:json',
                redactions,
            };
        }
        catch (err) {
            return { ...truncateAndSanitize(text, redactions), route: 'fallback:json-parse-error', redactions };
        }
    }
    if (AST_YAML_EXTENSIONS.has(ext)) {
        try {
            const parsed = yaml.parse(text);
            const { masked, wasModified } = maskObjectValues(parsed, 0, undefined, redactions);
            return {
                cleanText: yaml.stringify(masked, { indent: 2 }),
                wasModified,
                route: 'ast:yaml',
                redactions,
            };
        }
        catch (err) {
            return { ...truncateAndSanitize(text, redactions), route: 'fallback:yaml-parse-error', redactions };
        }
    }
    if (AST_XML_EXTENSIONS.has(ext)) {
        try {
            const parser = new fast_xml_parser_1.XMLParser(XML_PARSER_OPTS);
            const parsed = parser.parse(text);
            const { masked, wasModified } = maskObjectValues(parsed, 0, undefined, redactions);
            const builder = new fast_xml_parser_1.XMLBuilder({
                ...XML_PARSER_OPTS,
                format: true,
                suppressEmptyNode: false,
            });
            return {
                cleanText: builder.build(masked),
                wasModified,
                route: 'ast:xml',
                redactions,
            };
        }
        catch (err) {
            return { ...truncateAndSanitize(text, redactions), route: 'fallback:xml-parse-error', redactions };
        }
    }
    if (AST_ENV_EXTENSIONS.has(ext)) {
        try {
            const { cleanText, wasModified } = sanitizeEnvText(text, redactions);
            return { cleanText, wasModified, route: 'line:env', redactions };
        }
        catch (err) {
            return { ...truncateAndSanitize(text, redactions), route: 'fallback:env-parse-error', redactions };
        }
    }
    return { ...truncateAndSanitize(text, redactions), route: 'regex:catch-all', redactions };
}
//# sourceMappingURL=sanitizer.js.map