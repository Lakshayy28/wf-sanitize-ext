/**
 * router.ts — Smart Router & Content Sniffer
 * ═══════════════════════════════════════════
 * The traffic cop that directs files to the correct sanitization tier.
 *
 * Tier 1 (Bypass):     Source code → passed raw to LLM
 * Tier 2 (AST):        Structured configs → astSanitizer (key-match, no HTTP)
 * Tier 3 (Mega-Regex + NLP): Unstructured text → regexSanitizer + Presidio
 */

import * as vscode from 'vscode';
import type { AstFormat } from './astSanitizer';

// ────────────────────────────────────────────────────────────────────────────
// Safety blocklists
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

export interface RulesConfig {
  rules?: Record<string, string>;
  ast_extensions?: string[];
  full_dlp_extensions?: string[];
  custom_secrets?: CustomSecretDef[];
}

// ────────────────────────────────────────────────────────────────────────────
// File categories
// ────────────────────────────────────────────────────────────────────────────

export type FileCategory = 'bypass' | 'ast' | 'full_dlp';

// ────────────────────────────────────────────────────────────────────────────
// Default extension sets
// ────────────────────────────────────────────────────────────────────────────

/** Tier 2: AST-parsed structured configs — key-based masking, no Presidio. */
const DEFAULT_AST_EXTENSIONS = new Set([
  '.json', '.jsonc', '.jsonl', '.yaml', '.yml', '.env', '.properties', '.ini',
  '.xml', '.npmrc', '.kubeconfig', '.tfvars',
  // Config files
  '.conf', '.cfg', '.config', '.toml',
  // Tabular data
  '.csv', '.tsv',
  // Auth/Package Managers
  '.netrc', '.pgpass', '.gemrc', '.yarnrc',
  // Keys/Certs (have key=value structure)
  '.pem', '.key', '.cert', '.crt', '.pub', '.p12', '.ppk', '.cer', '.asc',
  // IaC
  '.tf', '.hcl', '.terraformrc', '.tfstate',
  // Build/Project
  '.csproj', '.props', '.targets', '.nuspec', '.kts',
  // Secrets
  '.secret',
  // Shell scripts (contain env var assignments)
  '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.psm1',
  // Docker/Make
  '.dockerfile', 'dockerfile', 'makefile', '.gradle',
  // XML schemas / services
  '.xsd', '.wsdl',
]);

/** Tier 3: Full DLP — regex + Shannon entropy + Presidio NLP. */
const DEFAULT_FULL_DLP_EXTENSIONS = new Set([
  '.txt', '.md', '.log',
  '.sql', '.graphql', '.gql',
  '.rtf',
]);

/**
 * Source-code extensions that should NEVER be scanned.
 * These are always bypassed — no regex, no Presidio, no AST.
 */
const SOURCE_CODE_BYPASS = new Set([
  // Systems languages
  '.c', '.h', '.cpp', '.cxx', '.cc', '.hpp', '.hxx', '.hh',
  '.m', '.mm',               // Objective-C
  '.rs',                     // Rust
  '.go',                     // Go
  '.swift',                  // Swift
  '.zig',                    // Zig
  // JVM
  '.java', '.scala', '.kt', '.groovy', '.clj', '.cljs',
  // .NET
  '.cs', '.fs', '.vb',
  // Web / Frontend
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx', '.mts', '.cts',
  '.vue', '.svelte', '.astro',
  '.html', '.htm', '.css', '.scss', '.sass', '.less', '.styl',
  // Scripting (NOT .sh/.bash/.ps1 — those are scanned for env vars)
  '.py', '.pyi', '.pyw',
  '.rb', '.erb',
  '.php', '.phtml',
  '.pl', '.pm',              // Perl
  '.lua',
  '.r', '.rmd',              // R
  '.jl',                     // Julia
  // Functional
  '.hs', '.lhs',             // Haskell
  '.ml', '.mli',             // OCaml
  '.ex', '.exs',             // Elixir
  '.erl', '.hrl',            // Erlang
  '.elm',                    // Elm
  '.dart',                   // Dart
  // Mobile
  '.kt', '.kts',             // Kotlin (also build scripts)
  // Assembly / low-level
  '.asm', '.s',
  // Misc
  '.d', '.nim', '.cr', '.v', '.zig',
  '.proto',                  // Protocol Buffers
  '.thrift',                 // Thrift IDL
  '.sol',                    // Solidity
  '.wgsl', '.glsl', '.hlsl', // Shaders
  '.cu', '.cuh',             // CUDA
  '.cmake',                  // CMake
  '.tcl',                    // Tcl
  '.ada', '.adb', '.ads',    // Ada
  '.pas', '.pp',             // Pascal/Delphi
  '.f', '.f90', '.f95',      // Fortran
  '.cob', '.cbl',            // COBOL
  '.lisp', '.el',            // Lisp / Emacs Lisp
  '.rkt',                    // Racket
]);

/**
 * Check whether an extension should be ignored (bypassed without scanning).
 * Merges the built-in SOURCE_CODE_BYPASS with user-configured extras from
 * `safechat.ignoreExtensions` setting.
 */
function isIgnoredExtension(ext: string): boolean {
  if (SOURCE_CODE_BYPASS.has(ext)) { return true; }
  try {
    const userIgnoreList: string[] =
      vscode.workspace.getConfiguration('safechat').get<string[]>('ignoreExtensions', []);
    for (const raw of userIgnoreList) {
      const normalized = raw.startsWith('.') ? raw.toLowerCase() : '.' + raw.toLowerCase();
      if (normalized === ext) { return true; }
    }
  } catch {
    // Outside VS Code context (unit tests) — just use built-in set
  }
  return false;
}

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


/**
 * Legacy content sniffer — maps unknown content to FileCategory.
 * Used by getFileCategory when an extension is unknown.
 */
function guessUnknownFileType(rawContent: string): FileCategory {
  const peek = rawContent.slice(0, 1000);

  // Shebang → scripts (AST tier for env var masking)
  if (peek.startsWith('#!/')) { return 'ast'; }

  // JSON or XML structure detection
  const trimmed = peek.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) { return 'full_dlp'; }
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<')) { return 'full_dlp'; }

  // Key=Value heuristic: >30% of lines match
  const lines = peek.split('\n').filter(l => l.trim().length > 0);
  if (lines.length > 0) {
    const kvCount = lines.filter(l => /^\s*[A-Za-z0-9_.\-]+\s*[=:]\s*.+/.test(l)).length;
    if (kvCount / lines.length > 0.3) { return 'ast'; }
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
export function getFileCategory(
  fileName: string,
  content?: string,
  config?: RulesConfig,
): FileCategory {
  // Source code bypass — always skip scanning for known code extensions
  const ext = extractExtension(fileName);
  if (ext && isIgnoredExtension(ext)) {
    return 'bypass';
  }

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
  const basename = fileName.split(/[/\\]/).pop()?.toLowerCase() ?? '';

  // Check extensionless filenames
  if (dlpSet.has(basename))  { return 'full_dlp'; }
  if (astSet.has(basename))  { return 'ast'; }

  if (!ext) {
    // No extension — use content sniffing if content provided
    if (content) { return guessUnknownFileType(content); }
    return 'bypass';
  }

  // Full DLP wins when an extension is in both sets
  if (dlpSet.has(ext)) { return 'full_dlp'; }
  if (astSet.has(ext)) { return 'ast'; }

  // Unknown extension — content sniff or bypass
  if (content) { return guessUnknownFileType(content); }
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
 *   custom_secrets:
 *     - name: "Acme Token"
 *       ast_keys: ["acme", "acme_pat"]
 *       value_prefix: "acme_live_"
 *       value_charset: "hex"
 *       value_length: "24"
 */
function parseRulesYaml(content: string): RulesConfig {
  const rules: Record<string, string> = {};
  const astExtensions: string[] = [];
  const fullDlpExtensions: string[] = [];
  const customSecrets: CustomSecretDef[] = [];
  let section: 'none' | 'rules' | 'ast_extensions' | 'full_dlp_extensions' | 'custom_secrets' = 'none';
  let currentSecret: Partial<CustomSecretDef> | null = null;

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

  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    const trimmed = line.trim();
    if (!trimmed) { continue; }

    // Top-level section headers
    if (trimmed === 'rules:')              { flushSecret(); section = 'rules';              continue; }
    if (trimmed === 'ast_extensions:')     { flushSecret(); section = 'ast_extensions';     continue; }
    if (trimmed === 'full_dlp_extensions:'){ flushSecret(); section = 'full_dlp_extensions'; continue; }
    if (trimmed === 'custom_secrets:')     { flushSecret(); section = 'custom_secrets';     continue; }

    // Must be indented to be inside a section
    if (!/^\s/.test(line)) { flushSecret(); section = 'none'; continue; }

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

    if (section === 'custom_secrets') {
      // New list item starts a new secret
      if (trimmed.startsWith('- ')) {
        flushSecret();
        currentSecret = {};
        const kvMatch = trimmed.slice(2).trim().match(/^(\w+)\s*:\s*(.+)/);
        if (kvMatch) {
          parseSecretKV(currentSecret, kvMatch[1], kvMatch[2]);
        }
      } else if (currentSecret) {
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
    custom_secrets: customSecrets.length > 0 ? customSecrets : undefined,
  };
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
 */
export async function readRulesConfig(): Promise<RulesConfig | undefined> {
  const config = vscode.workspace.getConfiguration('safechat');
  const rulesPath = config.get<string>('rulesFile') || '.vscode/safechat-rules.yaml';
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) { return undefined; }
  const rulesUri = vscode.Uri.joinPath(folders[0].uri, rulesPath);
  try {
    const bytes = await vscode.workspace.fs.readFile(rulesUri);
    return parseRulesYaml(Buffer.from(bytes).toString('utf-8'));
  } catch {
    return undefined;
  }
}
