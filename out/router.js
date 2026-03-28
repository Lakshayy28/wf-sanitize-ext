"use strict";
/**
 * router.ts — Smart Router & Content Sniffer
 * ═══════════════════════════════════════════
 * The traffic cop that directs files to the correct sanitization tier.
 *
 * Tier 1 (Bypass):     Source code → passed raw to LLM
 * Tier 2 (AST):        Structured configs → astSanitizer (key-match, no HTTP)
 * Tier 3 (Mega-Regex + NLP): Unstructured text → regexSanitizer + Presidio
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
exports.getAstFormat = getAstFormat;
exports.getFileCategory = getFileCategory;
exports.readRulesConfig = readRulesConfig;
const vscode = __importStar(require("vscode"));
// ────────────────────────────────────────────────────────────────────────────
// Default extension sets
// ────────────────────────────────────────────────────────────────────────────
/** Tier 2: AST-parsed structured configs — key-based masking, no Presidio. */
const DEFAULT_AST_EXTENSIONS = new Set([
    '.json', '.yaml', '.yml', '.env', '.properties', '.ini',
    '.xml', '.npmrc', '.kubeconfig', '.tfvars',
    // Config files
    '.conf', '.cfg', '.config', '.toml',
    // Auth/Package Managers
    '.netrc', '.pgpass', '.gemrc', '.yarnrc',
    // Keys/Certs (have key=value structure)
    '.pem', '.key', '.cert', '.crt', '.pub', '.p12', '.ppk', '.cer', '.asc',
    // IaC
    '.tf', '.hcl', '.terraformrc',
    // Build/Project
    '.csproj', '.props', '.targets', '.nuspec', '.kts',
    // Secrets
    '.secret',
    // Shell scripts (contain env var assignments)
    '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.psm1',
    // Docker/Make
    '.dockerfile', 'dockerfile', 'makefile', '.gradle',
]);
/** Tier 3: Full DLP — regex + Shannon entropy + Presidio NLP. */
const DEFAULT_FULL_DLP_EXTENSIONS = new Set([
    '.txt', '.md', '.log', '.csv', '.tsv',
    '.jsonl', '.sql', '.graphql', '.gql',
    '.xsd', '.wsdl', '.rtf',
]);
// ────────────────────────────────────────────────────────────────────────────
// AST format detection
// ────────────────────────────────────────────────────────────────────────────
/** Map file extensions to the AST parser format they should use. */
const AST_FORMAT_MAP = {
    // JSON
    '.json': 'json',
    // YAML
    '.yaml': 'yaml', '.yml': 'yaml', '.kubeconfig': 'yaml',
    // ENV
    '.env': 'env',
    // Properties / INI
    '.properties': 'properties', '.ini': 'properties', '.cfg': 'properties',
    '.npmrc': 'properties', '.netrc': 'properties', '.pgpass': 'properties',
    '.gemrc': 'properties', '.yarnrc': 'properties',
    '.conf': 'properties', '.config': 'properties', '.toml': 'properties',
    '.secret': 'properties', '.editorconfig': 'properties',
    // XML
    '.xml': 'xml', '.csproj': 'xml', '.props': 'xml', '.targets': 'xml',
    '.nuspec': 'xml', '.xsd': 'xml', '.wsdl': 'xml',
    // Key file formats (treat as env/properties for key: value lines)
    '.pem': 'env', '.key': 'env', '.cert': 'env', '.crt': 'env',
    '.pub': 'env', '.p12': 'env', '.ppk': 'env', '.cer': 'env', '.asc': 'env',
    // IaC (HCL is key=value like)
    '.tf': 'properties', '.tfvars': 'properties', '.hcl': 'properties',
    '.terraformrc': 'properties',
    // Build scripts (shell = env format)
    '.sh': 'env', '.bash': 'env', '.zsh': 'env', '.bat': 'env',
    '.cmd': 'env', '.ps1': 'env', '.psm1': 'env',
    '.dockerfile': 'env', '.gradle': 'properties', '.kts': 'properties',
};
/**
 * Returns the AST parser format for a given filename, or undefined if
 * no AST parser is appropriate.
 */
function getAstFormat(fileName) {
    const ext = extractExtension(fileName);
    if (!ext) {
        return undefined;
    }
    return AST_FORMAT_MAP[ext];
}
// ────────────────────────────────────────────────────────────────────────────
// Content Sniffer — for unknown extensions
// ────────────────────────────────────────────────────────────────────────────
/**
 * Guess the file type from its content when the extension is unknown.
 * Peeks at the first 1000 characters.
 */
function guessUnknownFileType(rawContent) {
    const peek = rawContent.slice(0, 1000);
    // Shebang → scripts (AST tier for env var masking)
    if (peek.startsWith('#!/')) {
        return 'ast';
    }
    // JSON or XML structure detection
    const trimmed = peek.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        return 'full_dlp';
    }
    if (trimmed.startsWith('<?xml') || trimmed.startsWith('<')) {
        return 'full_dlp';
    }
    // Key=Value heuristic: >30% of lines match
    const lines = peek.split('\n').filter(l => l.trim().length > 0);
    if (lines.length > 0) {
        const kvCount = lines.filter(l => /^\s*[A-Za-z0-9_.\-]+\s*[=:]\s*.+/.test(l)).length;
        if (kvCount / lines.length > 0.3) {
            return 'ast';
        }
    }
    // Source code indicators
    if (/\b(?:import|export|class|function|def|public|private|package|using|#include)\b/.test(peek)) {
        return 'bypass';
    }
    // Default: AST tier (safer — will attempt key=value masking)
    return 'ast';
}
// ────────────────────────────────────────────────────────────────────────────
// Main Router
// ────────────────────────────────────────────────────────────────────────────
/**
 * Determines the sanitization tier for a file.
 * Merges user config overrides into the default extension sets.
 *
 * @param fileName  — basename or relative path of the file
 * @param content   — optional raw content for content-sniffing unknown types
 * @param config    — optional rules config with user overrides
 */
function getFileCategory(fileName, content, config) {
    // Build working sets from defaults + user config
    const astSet = new Set(DEFAULT_AST_EXTENSIONS);
    const dlpSet = new Set(DEFAULT_FULL_DLP_EXTENSIONS);
    if (config?.ast_extensions) {
        for (const ext of config.ast_extensions) {
            const normalized = ext.startsWith('.') ? ext.toLowerCase() : '.' + ext.toLowerCase();
            astSet.add(normalized);
        }
    }
    if (config?.full_dlp_extensions) {
        for (const ext of config.full_dlp_extensions) {
            const normalized = ext.startsWith('.') ? ext.toLowerCase() : '.' + ext.toLowerCase();
            dlpSet.add(normalized);
        }
    }
    // Extract extension
    const ext = extractExtension(fileName);
    const basename = fileName.split(/[/\\]/).pop()?.toLowerCase() ?? '';
    // Check extensionless filenames
    if (dlpSet.has(basename)) {
        return 'full_dlp';
    }
    if (astSet.has(basename)) {
        return 'ast';
    }
    if (!ext) {
        // No extension — use content sniffing if content provided
        if (content) {
            return guessUnknownFileType(content);
        }
        return 'bypass';
    }
    // Full DLP wins when an extension is in both sets
    if (dlpSet.has(ext)) {
        return 'full_dlp';
    }
    if (astSet.has(ext)) {
        return 'ast';
    }
    // Unknown extension — content sniff or bypass
    if (content) {
        return guessUnknownFileType(content);
    }
    return 'bypass';
}
// ────────────────────────────────────────────────────────────────────────────
// YAML Config Reader
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
function normalizeEntityKey(key) {
    const slug = key.toLowerCase().replace(/[_\s-]/g, '');
    return ENTITY_ALIAS_MAP[slug] ?? key.toUpperCase().replace(/[\s-]/g, '_');
}
/**
 * Minimal YAML parser for safechat-rules.yaml — handles:
 *   rules:
 *     KeyName: Operation
 *   ast_extensions:
 *     - .custom_conf
 *   full_dlp_extensions:
 *     - .custom_log
 *   custom_secrets:
 *     - name: "Acme Token"
 *       ast_keys: ["acme", "acme_pat"]
 *       value_prefix: "acme_live_"
 *       value_charset: "hex"
 *       value_length: "24"
 */
function parseRulesYaml(content) {
    const rules = {};
    const astExtensions = [];
    const fullDlpExtensions = [];
    const customSecrets = [];
    let section = 'none';
    let currentSecret = null;
    function flushSecret() {
        if (currentSecret?.name) {
            customSecrets.push({
                name: currentSecret.name,
                ast_keys: currentSecret.ast_keys,
                value_prefix: currentSecret.value_prefix,
                value_charset: currentSecret.value_charset,
                value_length: currentSecret.value_length,
            });
        }
        currentSecret = null;
    }
    for (const raw of content.split('\n')) {
        const line = raw.replace(/#.*$/, '').trimEnd();
        const trimmed = line.trim();
        if (!trimmed) {
            continue;
        }
        // Top-level section headers
        if (trimmed === 'rules:') {
            flushSecret();
            section = 'rules';
            continue;
        }
        if (trimmed === 'ast_extensions:') {
            flushSecret();
            section = 'ast_extensions';
            continue;
        }
        if (trimmed === 'full_dlp_extensions:') {
            flushSecret();
            section = 'full_dlp_extensions';
            continue;
        }
        if (trimmed === 'custom_secrets:') {
            flushSecret();
            section = 'custom_secrets';
            continue;
        }
        // Must be indented to be inside a section
        if (!/^\s/.test(line)) {
            flushSecret();
            section = 'none';
            continue;
        }
        if (section === 'rules') {
            const m = trimmed.match(/^([A-Za-z0-9_]+)\s*:\s*([A-Za-z]+)/);
            if (m) {
                rules[m[1]] = m[2];
            }
        }
        if (section === 'ast_extensions' && trimmed.startsWith('- ')) {
            const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
            if (val) {
                astExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase());
            }
        }
        if (section === 'full_dlp_extensions' && trimmed.startsWith('- ')) {
            const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
            if (val) {
                fullDlpExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase());
            }
        }
        if (section === 'custom_secrets') {
            // New list item starts a new secret
            if (trimmed.startsWith('- ')) {
                flushSecret();
                currentSecret = {};
                const kvMatch = trimmed.slice(2).trim().match(/^(\w+)\s*:\s*(.+)/);
                if (kvMatch) {
                    parseSecretKV(currentSecret, kvMatch[1], kvMatch[2]);
                }
            }
            else if (currentSecret) {
                // Continuation of current secret properties
                const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.+)/);
                if (kvMatch) {
                    parseSecretKV(currentSecret, kvMatch[1], kvMatch[2]);
                }
            }
        }
    }
    flushSecret();
    // Normalize rule keys
    let normalizedRules;
    if (Object.keys(rules).length > 0) {
        normalizedRules = {};
        for (const [k, v] of Object.entries(rules)) {
            normalizedRules[normalizeEntityKey(k)] = v;
        }
    }
    return {
        rules: normalizedRules,
        ast_extensions: astExtensions.length > 0 ? astExtensions : undefined,
        full_dlp_extensions: fullDlpExtensions.length > 0 ? fullDlpExtensions : undefined,
        custom_secrets: customSecrets.length > 0 ? customSecrets : undefined,
    };
}
function parseSecretKV(secret, key, rawValue) {
    const value = rawValue.trim().replace(/^["']|["']$/g, '');
    switch (key) {
        case 'name':
            secret.name = value;
            break;
        case 'ast_keys':
            // Parse YAML inline array: ["acme", "acme_pat"]
            secret.ast_keys = value.replace(/[\[\]]/g, '').split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
            break;
        case 'value_prefix':
            secret.value_prefix = value;
            break;
        case 'value_charset':
            secret.value_charset = value;
            break;
        case 'value_length':
            secret.value_length = value;
            break;
    }
}
// Helper
function extractExtension(fileName) {
    const basename = fileName.split(/[/\\]/).pop() ?? '';
    const lastDot = basename.lastIndexOf('.');
    if (lastDot <= 0) {
        return undefined;
    }
    return basename.slice(lastDot).toLowerCase();
}
/**
 * Reads `.vscode/safechat-rules.yaml` (or the path from VS Code settings),
 * parses it, and returns the rules config.
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
        return parseRulesYaml(Buffer.from(bytes).toString('utf-8'));
    }
    catch {
        return undefined;
    }
}
//# sourceMappingURL=router.js.map