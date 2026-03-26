"use strict";
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
exports.readRulesConfig = readRulesConfig;
exports.regexSanitize = regexSanitize;
exports.stripAnsiCodes = stripAnsiCodes;
exports.contentSanitize = contentSanitize;
exports.terminalSanitize = terminalSanitize;
exports.sanitizePipeline = sanitizePipeline;
exports.sanitizeOnly = sanitizeOnly;
exports.sanitizeAndCache = sanitizeAndCache;
exports.viewDiffCommand = viewDiffCommand;
const vscode = __importStar(require("vscode"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
/** Reads the configured Presidio server base URL from VS Code settings. */
function getPresidioApiUrl() {
    const config = vscode.workspace.getConfiguration('safechat');
    return (config.get('presidioApiUrl') || 'http://localhost:8000').replace(/\/$/, '');
}
// ────────────────────────────────────────────────────────────────────────────
// Rules config (user-defined per-entity anonymization overrides)
// ────────────────────────────────────────────────────────────────────────────
/** Maps friendly alias names → canonical Presidio entity type strings. */
const ENTITY_ALIAS_MAP = {
    phonenumber: 'PHONE_NUMBER',
    phone: 'PHONE_NUMBER',
    accountnumber: 'US_BANK_NUMBER',
    bankaccount: 'US_BANK_NUMBER',
    email: 'EMAIL_ADDRESS',
    emailaddress: 'EMAIL_ADDRESS',
    emailaddr: 'EMAIL_ADDRESS',
    creditcard: 'CREDIT_CARD',
    cc: 'CREDIT_CARD',
    ssn: 'US_SSN',
    socialsecuritynumber: 'US_SSN',
    ipaddress: 'IP_ADDRESS',
    ip: 'IP_ADDRESS',
    person: 'PERSON',
    name: 'PERSON',
    url: 'URL',
    location: 'LOCATION',
    date: 'DATE_TIME',
    datetime: 'DATE_TIME',
    iban: 'IBAN_CODE',
    ibancode: 'IBAN_CODE',
    crypto: 'CRYPTO',
    bitcoin: 'CRYPTO',
    passport: 'US_PASSPORT',
    drivinglicense: 'US_DRIVER_LICENSE',
    driverslicense: 'US_DRIVER_LICENSE',
    medicallicense: 'MEDICAL_LICENSE',
    nrp: 'NRP',
};
/** Converts an alias or arbitrary casing to the canonical Presidio entity type. */
function normalizeEntityKey(key) {
    const slug = key.toLowerCase().replace(/[_\s-]/g, '');
    return ENTITY_ALIAS_MAP[slug] ?? key.toUpperCase().replace(/[\s-]/g, '_');
}
/**
 * Parses the subset of YAML needed for the rules file — no external deps.
 * Handles:
 *   rules:
 *     KeyName: Operation   # optional inline comment
 *   custom_recognizers:
 *     - name: EMPLOYEE_ID
 *       pattern: "EMP-\\d{6}"
 *       score: 0.85
 *       context:
 *         - employee
 *         - staff
 */
function parseRulesYaml(content) {
    const rules = {};
    const customRecognizers = [];
    const includeExtensions = [];
    let section = 'none';
    let currentItem = {};
    let currentContext = [];
    const flushItem = () => {
        if (currentItem.name && currentItem.pattern) {
            customRecognizers.push({
                name: currentItem.name,
                pattern: currentItem.pattern,
                score: currentItem.score ?? 0.85,
                context: currentContext.length > 0 ? currentContext : undefined,
            });
        }
        currentItem = {};
        currentContext = [];
    };
    for (const raw of content.split('\n')) {
        const line = raw.replace(/#.*$/, '').trimEnd();
        const trimmed = line.trim();
        if (!trimmed) {
            continue;
        }
        // Top-level section headers
        if (trimmed === 'rules:') {
            flushItem();
            section = 'rules';
            continue;
        }
        if (trimmed === 'custom_recognizers:') {
            flushItem();
            section = 'custom_recognizers';
            continue;
        }
        if (trimmed === 'include_extensions:') {
            flushItem();
            section = 'include_extensions';
            continue;
        }
        // Must be indented to be inside a section
        if (!/^\s/.test(line)) {
            flushItem();
            section = 'none';
            continue;
        }
        if (section === 'rules') {
            const m = trimmed.match(/^([A-Za-z0-9_]+)\s*:\s*([A-Za-z]+)/);
            if (m) {
                rules[m[1]] = m[2];
            }
        }
        // Simple string-list sections
        if (section === 'include_extensions' && trimmed.startsWith('- ')) {
            const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
            if (val) {
                includeExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase());
            }
            continue;
        }
        if (section === 'custom_recognizers' || section === 'custom_item' || section === 'custom_context') {
            // New list item starts with "- name:"
            if (trimmed.startsWith('- ')) {
                flushItem();
                section = 'custom_item';
                const m = trimmed.match(/^-\s+name\s*:\s*(.+)/);
                if (m) {
                    currentItem.name = m[1].trim().replace(/^["']|["']$/g, '');
                }
                continue;
            }
            if (section === 'custom_context') {
                // Collect context list items
                if (trimmed.startsWith('- ')) {
                    currentContext.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ''));
                    continue;
                }
                // No longer in context list
                section = 'custom_item';
            }
            if (section === 'custom_item') {
                const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.*)/);
                if (kvMatch) {
                    const key = kvMatch[1].toLowerCase();
                    const val = kvMatch[2].trim().replace(/^["']|["']$/g, '');
                    if (key === 'name') {
                        currentItem.name = val;
                    }
                    else if (key === 'pattern') {
                        currentItem.pattern = val;
                    }
                    else if (key === 'score') {
                        currentItem.score = parseFloat(val) || 0.85;
                    }
                    else if (key === 'context') {
                        // context can be inline [a, b] or a multi-line list
                        if (val.startsWith('[')) {
                            currentContext = val.replace(/[\[\]]/g, '').split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
                        }
                        else if (!val) {
                            section = 'custom_context';
                        }
                    }
                }
            }
        }
    }
    flushItem();
    return {
        rules: Object.keys(rules).length > 0 ? rules : undefined,
        customRecognizers: customRecognizers.length > 0 ? customRecognizers : undefined,
        includeExtensions: includeExtensions.length > 0 ? includeExtensions : undefined,
    };
}
/**
 * Reads `.vscode/safechat-rules.yaml` (or the path from VS Code settings),
 * parses it, and returns the rules config including any custom recognizers.
 * Returns `undefined` if the file doesn't exist.
 */
async function readRulesConfig() {
    const config = vscode.workspace.getConfiguration('safechat');
    const rulesPath = config.get('rulesFile') || '.vscode/safechat-rules.yaml';
    const folders = vscode.workspace.workspaceFolders;
    if (!folders?.length) {
        return undefined;
    }
    const rulesUri = vscode.Uri.joinPath(folders[0].uri, rulesPath);
    try {
        const bytes = await vscode.workspace.fs.readFile(rulesUri);
        const parsed = parseRulesYaml(Buffer.from(bytes).toString('utf-8'));
        // Normalize rule keys to canonical Presidio entity types
        let normalizedRules;
        if (parsed.rules) {
            normalizedRules = {};
            for (const [k, v] of Object.entries(parsed.rules)) {
                normalizedRules[normalizeEntityKey(k)] = v;
            }
            if (Object.keys(normalizedRules).length === 0) {
                normalizedRules = undefined;
            }
        }
        return {
            rules: normalizedRules,
            customRecognizers: parsed.customRecognizers,
            includeExtensions: parsed.includeExtensions,
        };
    }
    catch {
        return undefined; // file absent or unreadable → use server defaults
    }
}
/**
 * Calls the `/sanitize` endpoint on the running Presidio HTTP server.
 * Rejects if the server is unreachable or returns a non-2xx status.
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
        if (rulesConfig?.customRecognizers && rulesConfig.customRecognizers.length > 0) {
            payload.custom_recognizers = rulesConfig.customRecognizers;
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
// Regex-based secret masking (Tier 2 — fallback)
// ────────────────────────────────────────────────────────────────────────────
/**
 * A robust regex that matches common secret patterns:
 *  - Keys like password, passwd, secret, api_key, apikey, api-key, token,
 *    access_token, auth_token, private_key, client_secret, credentials, etc.
 *  - Followed by an assignment operator ( = , : , := , => ) with optional quotes.
 *  - Captures the value portion (the actual secret).
 *
 * Also matches standalone patterns:
 *  - Bearer tokens:       Bearer <token>
 *  - AWS keys:            AKIA[0-9A-Z]{16}
 *  - Generic hex/base64:  long high-entropy strings following a key name
 */
const SECRET_KEY_REGEX = new RegExp(
// ── Named-key = value patterns ───────────────────────────────────────
// Optional SET/export/ENV prefix (batch, shell, Dockerfile)
'(?:^|\\b)(?:SET\\s+|export\\s+|ENV\\s+)?' +
    '(' +
    // Key names (case-insensitive, broad coverage)
    '(?:password|passwd|pwd|secret|api_?key|api[-_]?secret|token|access_?token|' +
    'auth_?token|refresh_?token|private_?key|client_?secret|credentials|' +
    'database_?url|db_?url|db_?password|db_?pass|connection_?string|encryption_?key|' +
    'jwt_?secret|session_?secret|signing_?key|bearer|' +
    // AWS / cloud
    'aws_?access_?key_?id|aws_?secret_?access_?key|aws_?session_?token|' +
    // Additional common secret keys
    'secret_?key|auth_?key|admin_?password|admin_?secret|admin_?key|' +
    'smtp_?password|mail_?password|email_?password|' +
    'github_?token|gh_?token|gitlab_?token|npm_?token|' +
    'slack_?token|slack_?webhook|discord_?token|' +
    'stripe_?key|stripe_?secret|' +
    'sendgrid_?key|twilio_?auth|' +
    'redis_?url|redis_?password|mongo_?url|mongo_?uri|' +
    'mysql_?password|postgres_?password|' +
    'proxy_?password|ftp_?password|ssh_?password|' +
    'cert_?password|keystore_?password|truststore_?password)' +
    // Assignment operators with optional surrounding whitespace
    '\\s*[:=]\\s*' +
    // Optional opening quote
    '["\']?' +
    ')' +
    // The actual secret value (captured group 2)
    '([^\\s"\'`;,}{\\]\\)]+)' +
    '|' +
    // ── Email-like PII after common key names ────────────────────────────
    '(' +
    '(?:admin_?email|user_?email|contact_?email|email_?address|' +
    'email|mailto|from_?email|to_?email|reply_?to|' +
    'admin_?user|service_?account)' +
    '\\s*[:=]\\s*["\']?' +
    ')' +
    '([^\\s"\'`;,}{\\]\\)]+)' +
    '|' +
    // ── Phone/IP/hostname after common key names ─────────────────────────
    '(' +
    '(?:contact_?phone|phone_?number|phone|mobile|' +
    'server_?ip|host_?ip|ip_?address|remote_?addr|' +
    'server_?host|db_?host|hostname)' +
    '\\s*[:=]\\s*["\']?' +
    ')' +
    '([^\\s"\'`;,}{\\]\\)]+)' +
    '|' +
    // ── Standalone patterns ──────────────────────────────────────────────
    // Bearer tokens in Authorization headers
    '(Bearer\\s+)([A-Za-z0-9\\-._~+\\/]+=*)' +
    '|' +
    // AWS Access Key IDs
    '(AKIA[0-9A-Z]{16})', 'gim');
const MASK = '[MASKED_BY_SAFECHAT]';
/**
 * Sanitizes raw text by replacing detected secrets with a mask placeholder.
 * Returns the cleaned text and a flag indicating whether any replacements were made.
 */
function regexSanitize(rawText) {
    let wasModified = false;
    const cleanText = rawText.replace(SECRET_KEY_REGEX, (...args) => {
        wasModified = true;
        // Named-key = value / secrets  (groups 1, 2)
        if (args[1] && args[2]) {
            return (args[0].match(/^(?:SET\s+|export\s+|ENV\s+)/i)?.[0] ?? '') + args[1] + MASK;
        }
        // Email-like PII             (groups 3, 4)
        if (args[3] && args[4]) {
            return args[3] + MASK;
        }
        // Phone/IP/hostname          (groups 5, 6)
        if (args[5] && args[6]) {
            return args[5] + MASK;
        }
        // Bearer token               (groups 7, 8)
        if (args[7] && args[8]) {
            return args[7] + MASK;
        }
        // AWS key                    (group 9)
        if (args[9]) {
            return MASK;
        }
        return MASK;
    });
    return { cleanText, wasModified };
}
// ────────────────────────────────────────────────────────────────────────────
// Terminal-specific secret masking (Tier 3 — for tool output sanitization)
// ────────────────────────────────────────────────────────────────────────────
/** Known high-entropy secret prefixes (service-specific) */
const SECRET_PREFIXES = [
    'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', // GitHub tokens
    'sk-', // OpenAI / Stripe secret keys
    'pk_live_', 'pk_test_', // Stripe publishable keys
    'sk_live_', 'sk_test_', // Stripe secret keys
    'xoxb-', 'xoxp-', 'xoxs-', 'xoxa-', // Slack tokens
    'eyJ', // JWT (base64 header)
    'npm_', // npm tokens
    'AKIA', 'ASIA', // AWS key IDs
];
/**
 * Tests whether a string looks like a high-entropy secret (token, key, etc.)
 * using Shannon entropy and known prefix matching.
 */
function looksLikeSecret(s) {
    if (s.length < 16) {
        return false;
    }
    // Known prefixes
    if (SECRET_PREFIXES.some(p => s.startsWith(p))) {
        return true;
    }
    // Shannon entropy check
    const freq = new Map();
    for (const c of s) {
        freq.set(c, (freq.get(c) || 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    // High-entropy (>4 bits) AND at least 20 chars AND mix of character classes
    if (entropy > 4 && s.length >= 20) {
        const hasUpper = /[A-Z]/.test(s);
        const hasLower = /[a-z]/.test(s);
        const hasDigit = /[0-9]/.test(s);
        const hasSpecial = /[^A-Za-z0-9]/.test(s);
        const classes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
        return classes >= 3;
    }
    return false;
}
// ────────────────────────────────────────────────────────────────────────────
// Content-aware heuristic sanitizer (Tier 2b — unstructured text)
// ────────────────────────────────────────────────────────────────────────────
/** ANSI escape code stripper (SGR, cursor movement, erase sequences). */
const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]|\x1b\]\d*;[^\x07]*(?:\x07|\x1b\\)|\x1b[^\[\]][A-Za-z]/g;
/** Strip ANSI escape sequences while preserving all visible text. */
function stripAnsiCodes(text) {
    return text.replace(ANSI_RE, '');
}
/**
 * PEM private key block pattern.
 * Matches the full BEGIN/END block including the base64 body.
 */
const PEM_BLOCK_RE = /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g;
/**
 * Inline secret assignment patterns commonly found in code.
 * Catches hardcoded strings like `const apiKey = "sk-abc123..."` or
 * `password: 'hunter2'` across multiple programming languages.
 */
const INLINE_SECRET_ASSIGN_RE = new RegExp('(?:' +
    // JS/TS/Python/Ruby assignment: variable = 'value'
    '(?:const|let|var|val|def|my|local)?\\s*' +
    '(?:password|passwd|secret|api_?key|api_?secret|token|access_?token|auth_?token|' +
    'private_?key|client_?secret|jwt_?secret|session_?secret|signing_?key|encryption_?key|' +
    'database_?url|connection_?string|db_?password|redis_?password|mongo_?uri)' +
    '\\s*[:=]\\s*' +
    ')' +
    // Quoted value or bare value
    '(?:' +
    '(["\'])([^"\'>]{4,}?)\\1' + // quoted (groups 1,2)
    '|' +
    '([^\\s;,}{\\]\\)"\'>]{8,})' + // bare (group 3)
    ')', 'gi');
/**
 * Generic hex/base64 tokens that appear as bare string literals.
 * Targets long strings (32+ chars) of hex or base64 with known prefixes.
 */
const GENERIC_TOKEN_RE = /(?:^|["'`=:\s])([A-Za-z0-9+/\-_]{32,}={0,3})(?:["'`\s;,}\])]|$)/gm;
/**
 * Content-aware heuristic sanitizer for unstructured text.
 *
 * Processes raw multiline text (e.g., search result snippets) to catch:
 * - PEM private key blocks
 * - Inline hardcoded secrets in code (`const apiKey = "..."` etc.)
 * - Bare high-entropy tokens (32+ chars with Shannon entropy > 4)
 *
 * This function is intended to run AFTER `regexSanitize` as an additional
 * pass that catches secrets not in key=value format.
 */
function contentSanitize(text) {
    let wasModified = false;
    let result = text;
    // 1. Redact entire PEM private key blocks
    result = result.replace(PEM_BLOCK_RE, () => {
        wasModified = true;
        return MASK + '_PEM_KEY';
    });
    // 2. Inline secret assignments in code snippets
    result = result.replace(INLINE_SECRET_ASSIGN_RE, (match, quote, quotedVal, bareVal) => {
        wasModified = true;
        const val = quotedVal || bareVal;
        // Preserve the key/assignment portion, mask only the value
        return match.replace(val, MASK);
    });
    // 3. Line-by-line scan for bare high-entropy tokens
    const lines = result.split('\n');
    for (let i = 0; i < lines.length; i++) {
        // Reset regex state
        GENERIC_TOKEN_RE.lastIndex = 0;
        let lineModified = false;
        lines[i] = lines[i].replace(GENERIC_TOKEN_RE, (full, captured) => {
            // Skip tokens that look like file paths, URLs, or common programming identifiers
            if (/^(?:\/|\.\/|[a-z]:[/\\]|https?:|file:)/i.test(captured)) {
                return full;
            }
            if (/^(?:node_modules|package|function|return|import|export|require|undefined)/i.test(captured)) {
                return full;
            }
            if (looksLikeSecret(captured)) {
                lineModified = true;
                return full.replace(captured, MASK);
            }
            return full;
        });
        if (lineModified) {
            wasModified = true;
        }
    }
    if (wasModified) {
        result = lines.join('\n');
    }
    return { cleanText: result, wasModified };
}
/**
 * Terminal-specific sanitizer: applies narrow, targeted regexes for secrets
 * commonly seen in terminal/CLI output (curl headers, env vars, JSON fields,
 * CLI flags, Bearer tokens, AWS keys, bare high-entropy tokens).
 */
function terminalSanitize(text) {
    let wasModified = false;
    let result = text;
    // 1. CLI flags: --password=value, --token value, -p value
    result = result.replace(/(--(?:password|passwd|token|secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[=\s]\s*)(\S+)/gi, (_, prefix, val) => { wasModified = true; return prefix + MASK; });
    // 2. curl -H "Authorization: Bearer <token>" or -H "X-Api-Key: <value>"
    result = result.replace(/(-H\s+["'](?:Authorization|X-Api-Key|X-Auth-Token)\s*:\s*(?:Bearer\s+)?)([^"']+)(["'])/gi, (_, prefix, val, quote) => { wasModified = true; return prefix + MASK + quote; });
    // 3. JSON fields: "password": "value", "api_key": "value"
    result = result.replace(/(["'](?:password|passwd|secret|api_?key|token|access_?token|auth_?token|private_?key|client_?secret|jwt_?secret|session_?secret|signing_?key|encryption_?key|database_?url|connection_?string)["']\s*:\s*["'])([^"']+)(["'])/gi, (_, prefix, val, quote) => { wasModified = true; return prefix + MASK + quote; });
    // 4. Env var assignments: KEY=value (common in terminal output)
    result = result.replace(/((?:^|\n)\s*(?:export\s+|SET\s+|ENV\s+)?(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|PRIVATE_?KEY|CLIENT_?SECRET|AWS_?SECRET_?ACCESS_?KEY|AWS_?SESSION_?TOKEN|DATABASE_?URL|DB_?PASSWORD|REDIS_?PASSWORD|MONGO_?URI)=)(.+)/gim, (_, prefix, val) => { wasModified = true; return prefix + MASK; });
    // 5. Bearer tokens (standalone)
    result = result.replace(/(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)/gi, (_, prefix) => { wasModified = true; return prefix + MASK; });
    // 6. AWS Access Key IDs
    result = result.replace(/(?:AKIA|ASIA)[0-9A-Z]{16}/g, () => { wasModified = true; return MASK; });
    // 7. Bare high-entropy tokens (standalone words 20+ chars)
    result = result.replace(/(?<=\s|^)([A-Za-z0-9\-._~+/]{20,})(?=\s|$)/gm, (match) => {
        if (looksLikeSecret(match)) {
            wasModified = true;
            return MASK;
        }
        return match;
    });
    return { cleanText: result, wasModified };
}
/**
 * Unified sanitization pipeline — the single entry point for all tool output.
 *
 * Applies the appropriate sequence of sanitizers depending on the content's
 * origin:
 *
 *  **general** (default):   regexSanitize → contentSanitize
 *  **terminal**:            stripAnsiCodes → terminalSanitize → regexSanitize → contentSanitize
 *  **search**:              regexSanitize → contentSanitize  (same as general,
 *                           but semantically distinct for logging/future tuning)
 *
 * Every path ends with `contentSanitize` — the heuristic catch-all for
 * unstructured secrets (PEM keys, inline tokens, high-entropy strings).
 */
function sanitizePipeline(text, mode = 'general') {
    let current = text;
    let modified = false;
    // ── Terminal pre-processing: strip ANSI codes first ──────────────────
    if (mode === 'terminal') {
        current = stripAnsiCodes(current);
        // Terminal-specific patterns (CLI flags, curl headers, env vars, etc.)
        const termResult = terminalSanitize(current);
        current = termResult.cleanText;
        if (termResult.wasModified) {
            modified = true;
        }
    }
    // ── Tier 2: regex-based key=value + PII masking ──────────────────────
    const regexResult = regexSanitize(current);
    current = regexResult.cleanText;
    if (regexResult.wasModified) {
        modified = true;
    }
    // ── Tier 2b: content-aware heuristic scan ────────────────────────────
    const contentResult = contentSanitize(current);
    current = contentResult.cleanText;
    if (contentResult.wasModified) {
        modified = true;
    }
    return { cleanText: current, wasModified: modified };
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
// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────
/**
 * Sanitize text without writing any cache files.
 * Used by the per-file sanitization pipeline in extension.ts.
 *
 * Strategy:
 *  1. Try Presidio (Tier 1) for NLP-based PII masking.
 *  2. If Presidio is unavailable, fall back to the regex engine (Tier 2).
 *  3. The regex pass always runs *after* Presidio to catch secrets that
 *     NLP alone might miss (e.g., `api_key=...` patterns).
 */
async function sanitizeOnly(rawText, rulesConfig) {
    let presidioText = rawText;
    let presidioModified = false;
    let presidioError;
    try {
        const result = await callPresidioApi(rawText, rulesConfig);
        presidioText = result.sanitized_text;
        presidioModified = result.was_modified;
    }
    catch (err) {
        presidioError = err instanceof Error ? err.message : String(err);
    }
    const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
    const wasModified = presidioModified || regexModified;
    return { cleanText, wasModified, presidioError };
}
/**
 * Sanitize `rawText`, cache original + masked versions for diffing, and
 * return the clean text together with a modification flag.
 *
 * Strategy:
 *  1. Try Presidio (Tier 1) for NLP-based PII masking.
 *  2. If Presidio is unavailable, fall back to the regex engine (Tier 2).
 *  3. The regex pass always runs *after* Presidio to catch secrets that
 *     NLP alone might miss (e.g., `api_key=...` patterns).
 */
async function sanitizeAndCache(rawText, _extensionPath) {
    let presidioText = rawText;
    let presidioModified = false;
    let presidioError;
    // ── Tier 1: Presidio API masking ────────────────────────────────────
    const rulesConfig = await readRulesConfig();
    try {
        const result = await callPresidioApi(rawText, rulesConfig);
        presidioText = result.sanitized_text;
        presidioModified = result.was_modified;
    }
    catch (err) {
        // Server unreachable or returned an error — fall back to regex.
        presidioError = err instanceof Error ? err.message : String(err);
    }
    // ── Tier 2: Regex secret masking (always runs as a second pass) ────
    const { cleanText, wasModified: regexModified } = regexSanitize(presidioText);
    const wasModified = presidioModified || regexModified;
    if (wasModified) {
        const baseUri = getCacheBaseUri();
        if (baseUri) {
            await ensureCacheRoot(baseUri);
            // Each prompt gets its own timestamped subfolder — previous diffs are
            // never overwritten and remain on disk for manual inspection.
            const entryDir = vscode.Uri.joinPath(baseUri, timestampSlug());
            await vscode.workspace.fs.createDirectory(entryDir);
            const originalUri = vscode.Uri.joinPath(entryDir, 'original_context.txt');
            const maskedUri = vscode.Uri.joinPath(entryDir, 'masked_context.txt');
            await Promise.all([
                vscode.workspace.fs.writeFile(originalUri, Buffer.from(rawText, 'utf-8')),
                vscode.workspace.fs.writeFile(maskedUri, Buffer.from(cleanText, 'utf-8')),
            ]);
            // Update the in-memory pointer so the command-palette fallback works
            // after an extension reload (no button argument available then).
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
    // If the button passed a specific entry URI, use it directly.
    // This ensures each chat button always opens its own prompt's diff,
    // regardless of how many prompts have run since.
    if (entryUriString) {
        const entryUri = vscode.Uri.parse(entryUriString);
        const originalUri = vscode.Uri.joinPath(entryUri, 'original_context.txt');
        const maskedUri = vscode.Uri.joinPath(entryUri, 'masked_context.txt');
        await vscode.commands.executeCommand('vscode.diff', originalUri, maskedUri, `Original ↔ Sanitized  [${entryUri.path.split('/').pop()}]`);
        return;
    }
    // Fallback path: command palette invocation (no argument) — recover
    // the most recent entry from memory or disk.
    if (!latestCacheEntryUri) {
        // No in-memory pointer — extension may have reloaded. Try to recover the
        // most recent timestamped subfolder from disk.
        const baseUri = getCacheBaseUri();
        if (baseUri) {
            try {
                const entries = await vscode.workspace.fs.readDirectory(baseUri);
                const dirs = entries
                    .filter(([, type]) => type === vscode.FileType.Directory)
                    .map(([name]) => name)
                    .sort() // ISO timestamps sort lexicographically = chronologically
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