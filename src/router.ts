/**
 * router.ts — Whitelist-Only Context Router
 * ══════════════════════════════════════════
 * Strict Default-Deny architecture: ONLY files whose extension or path is
 * explicitly mapped (in the built-in defaults OR in safechat-rules.yaml)
 * are scanned. Everything else is bypassed.
 *
 * Routing priority:
 *   0. Binary blocklist          → blocked (never enters text pipeline)
 *   1. custom_paths (path match) → highest priority, user-defined strategy
 *   2. ast_extensions            → Tier 2 AST (pure-JS parsers)
 *   3. full_dlp_extensions       → Tier 3 Full DLP (server: regex + NLP)
 *   4. Default deny              → bypass (forwarded as-is, no scan)
 *
 * NO blacklists. NO content sniffing. NO guessing.
 */

import * as vscode from 'vscode';
import type { AstFormat } from './astSanitizer';
import type { PiiPatternsConfig } from './piiSanitizer';

// ────────────────────────────────────────────────────────────────────────────
// Safety: Binary blocklist (the ONLY blocklist — files that break parsers)
// ────────────────────────────────────────────────────────────────────────────

/** Binary extensions that must never enter the text pipeline. */
const BINARY_BLOCKLIST = new Set([
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg', '.tiff',
  '.mp3', '.mp4', '.wav', '.avi', '.mkv', '.mov', '.flac', '.ogg',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.obj', '.a', '.lib',
  '.wasm', '.class', '.pyc', '.pyo',
  '.sqlite', '.db', '.mdb', '.accdb',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.ttf', '.otf', '.woff', '.woff2', '.eot',
  '.p12', '.pfx', '.jks', '.keystore',
]);

/** Max file size (bytes) for full NLP pipeline. Above this → fast regex only. */
const MAX_NLP_FILE_SIZE = 1_000_000; // 1 MB

/** Max single-line length before we treat the file as minified. */
const MAX_LINE_LENGTH = 10_000;

// ────────────────────────────────────────────────────────────────────────────
// Config interfaces
// ────────────────────────────────────────────────────────────────────────────

export interface CustomSecretDef {
  name: string;
  ast_keys?: string[];
  value_prefix?: string;
  value_charset?: 'alphanumeric' | 'hex' | 'base64' | 'all';
  value_length?: string | number;
}

export interface CustomPathRule {
  path: string;
  strategy: 'AST' | 'FULL_DLP' | 'IGNORE';
}

export interface CustomRecognizerDef {
  name: string;
  pattern: string;
  score?: number;
  context?: string[];
}

export interface RulesConfig {
  rules?: Record<string, string>;
  ast_extensions?: string[];
  full_dlp_extensions?: string[];
  custom_paths?: CustomPathRule[];
  custom_secrets?: CustomSecretDef[];
  custom_recognizers?: CustomRecognizerDef[];
  /** Extra Tier-2 suffix tokens added to isSensitiveKey’s structural suffix check. */
  sensitive_suffixes?: string[];  /** Local PII engine config — enable/disable patterns and add custom ones. */
  pii_patterns?: PiiPatternsConfig;}

// ────────────────────────────────────────────────────────────────────────────
// File categories
// ────────────────────────────────────────────────────────────────────────────

export type FileCategory = 'bypass' | 'ast' | 'full_dlp';

// ────────────────────────────────────────────────────────────────────────────
// Built-in default extension whitelist
// ────────────────────────────────────────────────────────────────────────────
// These are the ONLY extensions that are scanned when no YAML is present.
// Users extend or override these via safechat-rules.yaml.

/** Tier 2: AST-parsed structured configs — key-based masking via server. */
const DEFAULT_AST_EXTENSIONS = new Set([
  // Data interchange
  '.json', '.jsonc', '.jsonl', '.yaml', '.yml',
  // Environment / Properties
  '.env', '.properties', '.ini', '.conf', '.cfg', '.config',
  '.toml', '.npmrc', '.kubeconfig',
  // Tabular data
  '.csv', '.tsv',
  // Auth / Package Managers
  '.netrc', '.pgpass', '.gemrc', '.yarnrc',
  // Keys / Certs (key=value structure)
  '.pem', '.key', '.cert', '.crt', '.pub', '.ppk', '.cer', '.asc',
  // IaC
  '.tf', '.hcl', '.terraformrc', '.tfstate', '.tfvars',
  // Build / Project (XML-based)
  '.csproj', '.props', '.targets', '.nuspec',
  '.xml', '.xsd', '.wsdl',
  // Secrets files
  '.secret',
  // Shell scripts (env var assignments)
  '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.psm1',
  // Docker / Build
  '.dockerfile', '.gradle', '.kts',
]);

/** Tier 3: Full DLP — regex + Shannon entropy + Presidio NLP (server-side). */
const DEFAULT_FULL_DLP_EXTENSIONS = new Set([
  '.txt', '.log', '.md',
  '.sql', '.graphql', '.gql',
  '.rtf',
]);

// ────────────────────────────────────────────────────────────────────────────
// AST format detection
// ────────────────────────────────────────────────────────────────────────────

/** Map file extensions to the AST parser format they should use. */
const AST_FORMAT_MAP: Record<string, AstFormat> = {
  // JSON (jsonc-parser handles comments + trailing commas)
  '.json': 'json', '.jsonc': 'jsonc', '.jsonl': 'jsonl', '.tfstate': 'json',
  // YAML
  '.yaml': 'yaml', '.yml': 'yaml', '.kubeconfig': 'yaml',
  // ENV
  '.env': 'env',
  // Properties / INI
  '.properties': 'properties', '.ini': 'properties', '.cfg': 'properties',
  '.npmrc': 'properties', '.netrc': 'properties', '.pgpass': 'properties',
  '.gemrc': 'properties', '.yarnrc': 'properties',
  '.conf': 'properties', '.config': 'properties',
  '.secret': 'properties', '.editorconfig': 'properties',
  // TOML
  '.toml': 'toml',
  // XML
  '.xml': 'xml', '.csproj': 'xml', '.props': 'xml', '.targets': 'xml',
  '.nuspec': 'xml', '.xsd': 'xml', '.wsdl': 'xml',
  // Key file formats (treat as env/properties for key: value lines)
  '.pem': 'env', '.key': 'env', '.cert': 'env', '.crt': 'env',
  '.pub': 'env', '.p12': 'env', '.ppk': 'env', '.cer': 'env', '.asc': 'env',
  // IaC (HCL)
  '.tf': 'hcl', '.tfvars': 'hcl', '.hcl': 'hcl',
  '.terraformrc': 'hcl',
  // CSV / TSV
  '.csv': 'csv', '.tsv': 'tsv',
  // Build scripts (shell = env format)
  '.sh': 'env', '.bash': 'env', '.zsh': 'env', '.bat': 'env',
  '.cmd': 'env', '.ps1': 'env', '.psm1': 'env',
  '.dockerfile': 'env', '.gradle': 'properties', '.kts': 'properties',
};

/**
 * Returns the AST parser format for a given filename, or undefined if
 * no AST parser is appropriate.
 */
export function getAstFormat(fileName: string): AstFormat | undefined {
  const ext = extractExtension(fileName);
  if (!ext) { return undefined; }
  return AST_FORMAT_MAP[ext];
}


// ────────────────────────────────────────────────────────────────────────────
// Main Router — Whitelist-Only (Default-Deny)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Normalize a file path for custom_paths matching.
 * Strips leading `./`, collapses separators, lowercases for comparison.
 */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
}

/**
 * Determines the sanitization tier for a file using strict whitelist logic.
 * Merges built-in defaults with user config from safechat-rules.yaml.
 *
 * Routing priority (evaluated in order):
 *   0. Binary blocklist          → bypass (binary safety)
 *   1. custom_paths (path match) → user-defined strategy (AST / FULL_DLP / IGNORE)
 *   2. ast_extensions whitelist  → Tier 2 AST
 *   3. full_dlp_extensions       → Tier 3 Full DLP
 *   4. Default deny              → bypass (not in whitelist = not scanned)
 *
 * @param fileName  — basename or relative path of the file
 * @param _content  — unused (kept for API compatibility; no content sniffing)
 * @param config    — optional rules config with user overrides
 */
export function getFileCategory(
  fileName: string,
  _content?: string,
  config?: RulesConfig,
): FileCategory {
  const ext = extractExtension(fileName);

  // ── Step 0: Binary blocklist ────────────────────────────────────────
  if (ext && BINARY_BLOCKLIST.has(ext)) {
    return 'bypass';
  }

  // ── Step 1: custom_paths (highest priority) ─────────────────────────
  if (config?.custom_paths && config.custom_paths.length > 0) {
    const normalizedFile = normalizePath(fileName);
    for (const rule of config.custom_paths) {
      const normalizedRule = normalizePath(rule.path);
      // Match if the file path ends with the rule path (supports both
      // relative and absolute incoming paths matching a relative rule)
      if (normalizedFile === normalizedRule || normalizedFile.endsWith('/' + normalizedRule)) {
        switch (rule.strategy) {
          case 'AST':      return 'ast';
          case 'FULL_DLP': return 'full_dlp';
          case 'IGNORE':   return 'bypass';
        }
      }
    }
  }

  // ── Step 2 & 3: Extension whitelist ─────────────────────────────────
  // Build merged sets: built-in defaults + user YAML additions
  const astSet = new Set(DEFAULT_AST_EXTENSIONS);
  const dlpSet = new Set(DEFAULT_FULL_DLP_EXTENSIONS);

  if (config?.ast_extensions) {
    for (const e of config.ast_extensions) {
      astSet.add(e.startsWith('.') ? e.toLowerCase() : '.' + e.toLowerCase());
    }
  }
  if (config?.full_dlp_extensions) {
    for (const e of config.full_dlp_extensions) {
      dlpSet.add(e.startsWith('.') ? e.toLowerCase() : '.' + e.toLowerCase());
    }
  }

  // Check extensionless filenames (e.g. "dockerfile", "makefile")
  const basename = fileName.split(/[/\\]/).pop()?.toLowerCase() ?? '';
  if (dlpSet.has(basename))  { return 'full_dlp'; }
  if (astSet.has(basename))  { return 'ast'; }

  if (!ext) {
    // No extension and no basename match → default deny
    return 'bypass';
  }

  // Full DLP wins when an extension is in both sets
  if (dlpSet.has(ext)) { return 'full_dlp'; }
  if (astSet.has(ext)) { return 'ast'; }

  // ── Step 4: Default deny ────────────────────────────────────────────
  return 'bypass';
}

// ────────────────────────────────────────────────────────────────────────────
// YAML Config Reader
// ────────────────────────────────────────────────────────────────────────────

/** Maps friendly alias names → canonical Presidio entity type strings. */
const ENTITY_ALIAS_MAP: Record<string, string> = {
  phonenumber:      'PHONE_NUMBER',
  phone:            'PHONE_NUMBER',
  accountnumber:    'US_BANK_NUMBER',
  bankaccount:      'US_BANK_NUMBER',
  email:            'EMAIL_ADDRESS',
  emailaddress:     'EMAIL_ADDRESS',
  emailaddr:        'EMAIL_ADDRESS',
  creditcard:       'CREDIT_CARD',
  cc:               'CREDIT_CARD',
  ssn:              'US_SSN',
  socialsecuritynumber: 'US_SSN',
  ipaddress:        'IP_ADDRESS',
  ip:               'IP_ADDRESS',
  person:           'PERSON',
  name:             'PERSON',
  url:              'URL',
  location:         'LOCATION',
  date:             'DATE_TIME',
  datetime:         'DATE_TIME',
  iban:             'IBAN_CODE',
  ibancode:         'IBAN_CODE',
  crypto:           'CRYPTO',
  bitcoin:          'CRYPTO',
  passport:         'US_PASSPORT',
  drivinglicense:   'US_DRIVER_LICENSE',
  driverslicense:   'US_DRIVER_LICENSE',
  medicallicense:   'MEDICAL_LICENSE',
  nrp:              'NRP',
};

function normalizeEntityKey(key: string): string {
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
 *   custom_paths:
 *     - path: "some/file.conf"
 *       strategy: "AST"
 *   custom_secrets:
 *     - name: "Acme Token"
 *       ast_keys: ["acme", "acme_pat"]
 *   custom_recognizers:
 *     - name: EMPLOYEE_ID
 *       pattern: "EMP-\\d{6}"
 *       score: 0.9
 *       context: [employee, staff]
 */
type YamlSection = 'none' | 'rules' | 'ast_extensions' | 'full_dlp_extensions'
  | 'custom_secrets' | 'custom_paths' | 'custom_recognizers';

function parseRulesYaml(content: string): RulesConfig {
  const rules: Record<string, string> = {};
  const astExtensions: string[] = [];
  const fullDlpExtensions: string[] = [];
  const customSecrets: CustomSecretDef[] = [];
  const customPaths: CustomPathRule[] = [];
  const customRecognizers: CustomRecognizerDef[] = [];
  let section: YamlSection = 'none';
  let currentSecret: Partial<CustomSecretDef> | null = null;
  let currentPath: Partial<CustomPathRule> | null = null;
  let currentRecognizer: Partial<CustomRecognizerDef> | null = null;

  function flushSecret(): void {
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

  function flushPath(): void {
    if (currentPath?.path && currentPath?.strategy) {
      customPaths.push({
        path: currentPath.path,
        strategy: currentPath.strategy,
      });
    }
    currentPath = null;
  }

  function flushRecognizer(): void {
    if (currentRecognizer?.name && currentRecognizer?.pattern) {
      customRecognizers.push({
        name: currentRecognizer.name,
        pattern: currentRecognizer.pattern,
        score: currentRecognizer.score,
        context: currentRecognizer.context,
      });
    }
    currentRecognizer = null;
  }

  function flushAll(): void { flushSecret(); flushPath(); flushRecognizer(); }

  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    const trimmed = line.trim();
    if (!trimmed) { continue; }

    // Top-level section headers (support both flat and nested under scanning_rules:)
    if (trimmed === 'scanning_rules:')     { continue; } // wrapper — skip
    if (trimmed === 'rules:')              { flushAll(); section = 'rules';              continue; }
    if (trimmed === 'ast_extensions:')     { flushAll(); section = 'ast_extensions';     continue; }
    if (trimmed === 'full_dlp_extensions:'){ flushAll(); section = 'full_dlp_extensions'; continue; }
    if (trimmed === 'custom_secrets:')     { flushAll(); section = 'custom_secrets';     continue; }
    if (trimmed === 'custom_paths:')       { flushAll(); section = 'custom_paths';       continue; }
    if (trimmed === 'custom_recognizers:') { flushAll(); section = 'custom_recognizers'; continue; }

    // Must be indented to be inside a section
    if (!/^\s/.test(line)) { flushAll(); section = 'none'; continue; }

    if (section === 'rules') {
      const m = trimmed.match(/^([A-Za-z0-9_]+)\s*:\s*([A-Za-z]+)/);
      if (m) { rules[m[1]] = m[2]; }
    }

    if (section === 'ast_extensions' && trimmed.startsWith('- ')) {
      const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
      if (val) { astExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase()); }
    }

    if (section === 'full_dlp_extensions' && trimmed.startsWith('- ')) {
      const val = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
      if (val) { fullDlpExtensions.push(val.startsWith('.') ? val.toLowerCase() : '.' + val.toLowerCase()); }
    }

    if (section === 'custom_paths') {
      if (trimmed.startsWith('- ')) {
        flushPath();
        currentPath = {};
        const kvMatch = trimmed.slice(2).trim().match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parsePathKV(currentPath, kvMatch[1], kvMatch[2]); }
      } else if (currentPath) {
        const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parsePathKV(currentPath, kvMatch[1], kvMatch[2]); }
      }
    }

    if (section === 'custom_secrets') {
      if (trimmed.startsWith('- ')) {
        flushSecret();
        currentSecret = {};
        const kvMatch = trimmed.slice(2).trim().match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parseSecretKV(currentSecret, kvMatch[1], kvMatch[2]); }
      } else if (currentSecret) {
        const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parseSecretKV(currentSecret, kvMatch[1], kvMatch[2]); }
      }
    }

    if (section === 'custom_recognizers') {
      if (trimmed.startsWith('- ')) {
        flushRecognizer();
        currentRecognizer = {};
        const kvMatch = trimmed.slice(2).trim().match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parseRecognizerKV(currentRecognizer, kvMatch[1], kvMatch[2]); }
      } else if (currentRecognizer) {
        const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) { parseRecognizerKV(currentRecognizer, kvMatch[1], kvMatch[2]); }
      }
    }
  }

  flushAll();

  // Normalize rule keys
  let normalizedRules: Record<string, string> | undefined;
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
    custom_paths: customPaths.length > 0 ? customPaths : undefined,
    custom_secrets: customSecrets.length > 0 ? customSecrets : undefined,
    custom_recognizers: customRecognizers.length > 0 ? customRecognizers : undefined,
  };
}

function parsePathKV(pathRule: Partial<CustomPathRule>, key: string, rawValue: string): void {
  const value = rawValue.trim().replace(/^["']|["']$/g, '');
  switch (key) {
    case 'path':
      pathRule.path = value;
      break;
    case 'strategy':
      pathRule.strategy = value.toUpperCase() as CustomPathRule['strategy'];
      break;
  }
}

function parseSecretKV(secret: Partial<CustomSecretDef>, key: string, rawValue: string): void {
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
      secret.value_charset = value as CustomSecretDef['value_charset'];
      break;
    case 'value_length':
      secret.value_length = value;
      break;
  }
}

function parseRecognizerKV(rec: Partial<CustomRecognizerDef>, key: string, rawValue: string): void {
  const value = rawValue.trim().replace(/^["']|["']$/g, '');
  switch (key) {
    case 'name':
      rec.name = value;
      break;
    case 'pattern':
      rec.pattern = value;
      break;
    case 'score':
      rec.score = parseFloat(value) || undefined;
      break;
    case 'context':
      // Parse YAML inline array or block sequence
      rec.context = value.replace(/[\[\]]/g, '').split(',')
        .map(s => s.trim().replace(/^["'-]?\s*|["']$/g, '')).filter(Boolean);
      break;
  }
}

// Helper
function extractExtension(fileName: string): string | undefined {
  const basename = fileName.split(/[/\\]/).pop() ?? '';
  const lastDot = basename.lastIndexOf('.');
  if (lastDot <= 0) { return undefined; }
  return basename.slice(lastDot).toLowerCase();
}

/**
 * Reads `.vscode/safechat-rules.yaml` (or the path from VS Code settings),
 * parses it, and returns the rules config.
 *
 * If the YAML file does not exist, returns an empty config (the router
 * falls back to hardcoded DEFAULT_AST_EXTENSIONS / DEFAULT_FULL_DLP_EXTENSIONS).
 */
export async function readRulesConfig(): Promise<RulesConfig> {
  const config = vscode.workspace.getConfiguration('safechat');
  const rulesPath = config.get<string>('rulesFile') || '.vscode/safechat-rules.yaml';
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) { return {}; }
  const rulesUri = vscode.Uri.joinPath(folders[0].uri, rulesPath);
  try {
    const bytes = await vscode.workspace.fs.readFile(rulesUri);
    return parseRulesYaml(Buffer.from(bytes).toString('utf-8'));
  } catch {
    return {};
  }
}
