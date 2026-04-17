/**
 * sanitizer.ts — Smart Proxy: Polyglot AST Router + Regex DLP Engine
 * ════════════════════════════════════════════════════════════════════
 *
 * Architecture:
 *   1. smartSanitize(text, ext?) — The public entry point.
 *      Routes structured formats (JSON, YAML, XML, ENV/INI) through
 *      format-aware AST parsing → selective value masking → reconstruction.
 *      Code files are bypassed entirely.  Unstructured text falls through
 *      to the truncation + regex catch-all.
 *
 *   2. maskObjectValues(obj) — Recursive Universal Object Masker.
 *      Walks any JS object/array tree.  String leaves are piped through
 *      regexSanitize().  Primitives pass through untouched.
 *
 *   3. regexSanitize(text) — 22-pattern enterprise dictionary.
 *      Sequential replacement with capture-group-aware masking.
 *
 *   4. truncateAndSanitize(text) — 250KB budget guard.
 *      Slices at the nearest newline, then runs regexSanitize().
 *
 * Every AST parser is wrapped in try/catch.  Parse failures NEVER
 * fail-open — they fall through to truncateAndSanitize().
 */

import * as yaml from 'yaml';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

export const MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000; // 250 KB
const IS_DEV_MODE = true;

/**
 * Dual-Mode Logger: Avoids CWE-532 (Sensitive Logging) in production.
 */
function logRedaction(patternName: string, matchedSecret: string): void {
  if (IS_DEV_MODE) {
    console.warn(`[SafeChat DEBUG] Redacted ${patternName}: "${matchedSecret}"`);
  } else {
    console.info(`[SafeChat AUDIT] Redacted ${patternName} (length: ${matchedSecret.length})`);
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Secret Pattern Dictionary (22 Enterprise Regex Patterns)
// ────────────────────────────────────────────────────────────────────────────

export interface SecretPattern {
  name: string;
  regex: RegExp;
  /** When true the regex uses 3 capture groups: protocol (G1), auth (G2), @host (G3). */
  isUrlAuth?: boolean;
}

export const HIGH_CONFIDENCE_SECRETS: SecretPattern[] = [
  // ── Cloud & CI/CD ─────────────────────────────────────────────────────
  { name: 'AWS Access Key',         regex: /\b(AKIA[0-9A-Z]{16})\b/g },
  { name: 'GCP Service Account',    regex: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY[\s\S]*?-----END PRIVATE KEY-----\\n)"/g },
  { name: 'Azure Shared Key',       regex: /\bAccountKey=([A-Za-z0-9+/]{86}==)\b/g },
  { name: 'GitHub Token',           regex: /\b(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b/g },
  { name: 'GitLab Token',           regex: /\b(glpat-[A-Za-z0-9_\-]{20})\b/g },
  { name: 'Jenkins Token',          regex: /\b(11[a-f0-9]{32})\b/g },
  { name: 'Harness Token',          regex: /\b(?:pat|sat)\.[A-Za-z0-9_-]{20,}\.([A-Za-z0-9_-]{20,})\b/g },
  { name: 'OpenShift Token',        regex: /\b(sha256~[A-Za-z0-9_\-]{43})\b/g },
  { name: 'LambdaTest/SauceLabs',   regex: /(?:https?:\/\/)[a-zA-Z0-9_.-]+:([a-zA-Z0-9]{32,64})@hub\.(?:lambdatest|saucelabs)\.com/g },

  // ── APIs & Comms ──────────────────────────────────────────────────────
  { name: 'Slack Token',            regex: /\b(xox[bpas]-[0-9A-Za-z\-]+)\b/g },
  { name: 'Stripe Key',             regex: /\b([spr]k_(?:live|test)_[A-Za-z0-9]{24,})\b/g },
  { name: 'SendGrid Key',           regex: /\b(SG\.[A-Za-z0-9\-_]{16,32}\.[A-Za-z0-9\-_]{32,64})\b/g },
  { name: 'NPM Token',              regex: /\b(npm_[a-zA-Z0-9]{36})\b/g },
  { name: 'HashiCorp Vault Token',  regex: /\b((?:hvs|hvb|hvr|s)\.[A-Za-z0-9_\-]{24,120})\b/g },
  { name: 'SonarQube Token',        regex: /\b(sq[pua]_[A-Za-z0-9]{40})\b/g },
  { name: 'Terraform Cloud Token',  regex: /\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67})\b/g },
  { name: 'Bitbucket Token',        regex: /\b(ATBB[A-Za-z0-9]{28}|ATCTT[A-Za-z0-9]{171,})\b/g },

  // ── Cryptographic Material ────────────────────────────────────────────
  { name: 'RSA/PEM Private Key',    regex: /(-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----)/g },
  { name: 'JWT Token',              regex: /\b(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)\b/g },

  // ── Generic URL Secrets ───────────────────────────────────────────────
  { name: 'URL Query Parameter Secret', regex: /(?:password|passwd|secret|token|api_?key|auth)=([^&\s"']+)/gi },
  { name: 'Credential URL', regex: /\b([a-zA-Z0-9+.-]+:\/\/)([^@\s]+)(@[a-zA-Z0-9.-]+(?::[\d]+)?(?:\/[^\s"']*)?)/gi, isUrlAuth: true },

  // ── Keyless Credential Files ──────────────────────────────────────────
  { name: 'Netrc Password', regex: /(?:password|passwd)\s+([^\s]+)/gi },
  { name: 'Pgpass Password', regex: /^(?:[^:\r\n]+:){4}([^:\r\n]+)$/gm },

  // ── Standard PII Fallback ─────────────────────────────────────────────
  { name: 'US SSN',                  regex: /\b(\d{3}-\d{2}-\d{4})\b/g },
  { name: 'Credit Card Number',      regex: /\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7})\b/g },
  { name: 'IBAN Code',               regex: /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g },
  { name: 'IPv4 Address',            regex: /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g },
  { name: 'Internal Hostname',       regex: /\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.(?:internal|local|private)\b/gi },
  { name: 'MAC Address',             regex: /(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/g },
  { name: 'Certificate Thumbprint',  regex: /(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}/g },
  { name: 'Email Address',           regex: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
  { name: 'Phone Number Fallback',   regex: /(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
];

// ────────────────────────────────────────────────────────────────────────────
// Configuration Management (`safechat.yml` dynamic routing)
// ────────────────────────────────────────────────────────────────────────────

// Routing sets (mutable base configs)
let BYPASS_EXTENSIONS = new Set<string>();
let AST_JSON_EXTENSIONS = new Set<string>();
let AST_YAML_EXTENSIONS = new Set<string>();
let AST_XML_EXTENSIONS = new Set<string>();
let AST_ENV_EXTENSIONS = new Set<string>();
let DYNAMIC_PATTERNS: SecretPattern[] = [];

// Defaults (Fallback)
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
  '.m', '.mm',         // Objective-C
  '.dart',
  '.lua',
  '.r', '.R',
  '.pl', '.pm',        // Perl
  '.sh', '.bash', '.zsh', '.fish',
  '.ps1', '.psm1',     // PowerShell
  '.sql',
  '.vue', '.svelte',
  '.tf', '.hcl',       // Terraform / HCL
  '.proto',
  '.graphql', '.gql',
];

const DEFAULT_AST_JSON = ['.json', '.jsonc', '.json5'];
const DEFAULT_AST_YAML = ['.yaml', '.yml'];
const DEFAULT_AST_XML  = ['.xml', '.xsl', '.xslt', '.svg', '.plist'];
const DEFAULT_AST_ENV  = ['.env', '.ini', '.cfg', '.properties', '.env.local', '.env.production', '.env.development'];

function resetToDefaults() {
  BYPASS_EXTENSIONS = new Set(DEFAULT_BYPASS);
  AST_JSON_EXTENSIONS = new Set(DEFAULT_AST_JSON);
  AST_YAML_EXTENSIONS = new Set(DEFAULT_AST_YAML);
  AST_XML_EXTENSIONS = new Set(DEFAULT_AST_XML);
  AST_ENV_EXTENSIONS = new Set(DEFAULT_AST_ENV);
  DYNAMIC_PATTERNS = [];
}

// Initial bootstrap
resetToDefaults();

/**
 * Updates dynamic configuration arrays/sets based on safechat.yml.
 * If config is null/undefined, resets to hardcoded defaults.
 */
export function updateConfig(config: any) {
  if (!config) {
    console.log('[SafeChat] Config absent or removed. Resetting to defaults.');
    resetToDefaults();
    return;
  }

  // Populate Extensions Sets if supplied 
  if (config.routing) {
    if (Array.isArray(config.routing.bypass)) { BYPASS_EXTENSIONS = new Set(config.routing.bypass); }
    if (Array.isArray(config.routing.ast_json)) { AST_JSON_EXTENSIONS = new Set(config.routing.ast_json); }
    if (Array.isArray(config.routing.ast_yaml)) { AST_YAML_EXTENSIONS = new Set(config.routing.ast_yaml); }
    if (Array.isArray(config.routing.ast_xml)) { AST_XML_EXTENSIONS = new Set(config.routing.ast_xml); }
    if (Array.isArray(config.routing.ast_env)) { AST_ENV_EXTENSIONS = new Set(config.routing.ast_env); }
  } else {
    // If routing block isn't present, preserve defaults
    resetToDefaults();
  }

  // Populate Custom Regex Patterns
  DYNAMIC_PATTERNS = [];
  if (Array.isArray(config.custom_patterns)) {
    for (const pat of config.custom_patterns) {
      if (pat.name && pat.regex) {
        try {
          // Use 'g' flag for sequential replacement
          let r = new RegExp(pat.regex, 'g');
          DYNAMIC_PATTERNS.push({ name: pat.name, regex: r });
        } catch (err) {
          console.warn(`[SafeChat] Failed to compile regex for custom pattern "${pat.name}":`, err);
        }
      }
    }
  }

  console.log('[SafeChat] Configuration updated successfully from safechat.yml.');
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 1: Pure Regex Sanitizer
// ────────────────────────────────────────────────────────────────────────────

/**
 * Runs the 22-pattern enterprise regex dictionary + dynamic patterns.
 * Every pattern uses `lastIndex`-reset via fresh `.replace()` calls
 * to avoid stale-state bugs on global regexes.
 */
export function regexSanitize(text: string): { cleanText: string; wasModified: boolean } {
  let wasModified = false;
  let current = text;

  // Combine built-in secrets with user-defined dynamic patterns
  const allPatterns = [...HIGH_CONFIDENCE_SECRETS, ...DYNAMIC_PATTERNS];

  for (const pattern of allPatterns) {
    // Reset lastIndex for global regexes to avoid stale state
    pattern.regex.lastIndex = 0;

    if (pattern.isUrlAuth) {
      const replaced = current.replace(pattern.regex, (_full, proto, _auth, host) => {
        wasModified = true;
        logRedaction(pattern.name, _auth);
        return `${proto}${MASK}${host}`;
      });
      if (replaced !== current) { current = replaced; }
    } else {
      const replaced = current.replace(pattern.regex, (full, captured) => {
        wasModified = true;
        const secretValue = captured !== undefined ? captured : full;
        logRedaction(pattern.name, secretValue);
        if (captured !== undefined) {
          return full.replace(captured, MASK);
        }
        return MASK;
      });
      if (replaced !== current) { current = replaced; }
    }
  }

  return { cleanText: current, wasModified };
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 2: Universal Object Masker (recursive AST walker)
// ────────────────────────────────────────────────────────────────────────────

/** Maximum recursion depth to prevent stack overflow on adversarial inputs. */
const MAX_DEPTH = 64;

/**
 * Recursively walks any JS object/array tree.
 * - Strings  → piped through `regexSanitize()`.
 * - Arrays   → mapped recursively.
 * - Objects  → keys preserved, values recursively masked.
 * - Primitives (number, boolean, null, undefined) → returned as-is.
 *
 * Returns `{ masked, wasModified }` so callers know if anything changed.
 */
export function maskObjectValues(
  obj: unknown,
  depth: number = 0,
): { masked: unknown; wasModified: boolean } {
  // Depth guard
  if (depth > MAX_DEPTH) {
    return { masked: obj, wasModified: false };
  }

  // Null / undefined
  if (obj === null || obj === undefined) {
    return { masked: obj, wasModified: false };
  }

  // String — the leaf node where actual scanning happens
  if (typeof obj === 'string') {
    const { cleanText, wasModified } = regexSanitize(obj);
    return { masked: cleanText, wasModified };
  }

  // Primitive passthrough (number, boolean, bigint, symbol)
  if (typeof obj !== 'object') {
    return { masked: obj, wasModified: false };
  }

  // Array — map recursively
  if (Array.isArray(obj)) {
    let anyModified = false;
    const maskedArr = obj.map(item => {
      const { masked, wasModified } = maskObjectValues(item, depth + 1);
      if (wasModified) { anyModified = true; }
      return masked;
    });
    return { masked: maskedArr, wasModified: anyModified };
  }

  // Object — iterate keys, recursively mask values, leave keys intact
  let anyModified = false;
  const maskedObj: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const { masked, wasModified } = maskObjectValues(value, depth + 1);
    maskedObj[key] = masked;
    if (wasModified) { anyModified = true; }
  }
  return { masked: maskedObj, wasModified: anyModified };
}

// ────────────────────────────────────────────────────────────────────────────
// Truncation + Regex Fallback (catch-all for unstructured text)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Enforces a 250KB byte budget, then runs the regex dictionary.
 * Truncation slices at the nearest preceding newline to avoid splitting
 * tokens or credentials mid-match.
 */
export function truncateAndSanitize(text: string): { cleanText: string; wasModified: boolean } {
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
  }

  const { cleanText, wasModified } = regexSanitize(current);
  return { cleanText, wasModified: wasModified || wasTruncated };
}

// ────────────────────────────────────────────────────────────────────────────
// ENV / INI line-by-line parser
// ────────────────────────────────────────────────────────────────────────────

function sanitizeEnvText(text: string): { cleanText: string; wasModified: boolean } {
  let wasModified = false;
  const lines = text.split('\n');

  const sanitizedLines = lines.map(line => {
    const trimmed = line.trim();

    // Preserve comments and blank lines
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) {
      return line;
    }

    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) {
      // No assignment — run regex on the whole line
      const { cleanText, wasModified: lm } = regexSanitize(line);
      if (lm) { wasModified = true; }
      return cleanText;
    }

    const key = line.slice(0, eqIdx);
    let value = line.slice(eqIdx + 1);

    // Strip optional surrounding quotes for scanning, then re-wrap
    let quote = '';
    const trimVal = value.trim();
    if ((trimVal.startsWith('"') && trimVal.endsWith('"')) ||
        (trimVal.startsWith("'") && trimVal.endsWith("'"))) {
      quote = trimVal[0];
      value = trimVal.slice(1, -1);
    }

    const { cleanText: maskedVal, wasModified: vm } = regexSanitize(value);
    if (vm) { wasModified = true; }

    return quote
      ? `${key}=${quote}${maskedVal}${quote}`
      : `${key}=${maskedVal}`;
  });

  return { cleanText: sanitizedLines.join('\n'), wasModified };
}

// ────────────────────────────────────────────────────────────────────────────
// XML parser config (shared between parser and builder)
// ────────────────────────────────────────────────────────────────────────────

const XML_PARSER_OPTS = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  preserveOrder: false,
  trimValues: false,
};

// ────────────────────────────────────────────────────────────────────────────
// The Smart Router (public entry point)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Routes text through the appropriate sanitization pathway based on file
 * extension.  Structured formats are parsed → masked → reconstructed.
 * Code files are bypassed.  Unknown / unstructured text falls through to
 * the 250KB truncation + pure regex catch-all.
 *
 * **Every AST parser is try/catch'd.  Parse failures NEVER fail-open —
 * they fall through to `truncateAndSanitize()` (fail-closed).**
 */
export function smartSanitize(
  text: string,
  fileExtension?: string,
): { cleanText: string; wasModified: boolean; route: string } {
  const ext = (fileExtension ?? '').toLowerCase().replace(/^\.?/, '.');

  // ── Code files: bypass completely ─────────────────────────────────────
  if (BYPASS_EXTENSIONS.has(ext)) {
    return { cleanText: text, wasModified: false, route: 'bypass:code' };
  }

  // ── JSON ──────────────────────────────────────────────────────────────
  if (AST_JSON_EXTENSIONS.has(ext)) {
    try {
      const parsed = JSON.parse(text);
      const { masked, wasModified } = maskObjectValues(parsed);
      return {
        cleanText: JSON.stringify(masked, null, 2),
        wasModified,
        route: 'ast:json',
      };
    } catch (err) {
      console.warn('[SafeChat] JSON parse failed, falling back to regex:', err);
      return { ...truncateAndSanitize(text), route: 'fallback:json-parse-error' };
    }
  }

  // ── YAML ──────────────────────────────────────────────────────────────
  if (AST_YAML_EXTENSIONS.has(ext)) {
    try {
      const parsed = yaml.parse(text);
      const { masked, wasModified } = maskObjectValues(parsed);
      return {
        cleanText: yaml.stringify(masked, { indent: 2 }),
        wasModified,
        route: 'ast:yaml',
      };
    } catch (err) {
      console.warn('[SafeChat] YAML parse failed, falling back to regex:', err);
      return { ...truncateAndSanitize(text), route: 'fallback:yaml-parse-error' };
    }
  }

  // ── XML ───────────────────────────────────────────────────────────────
  if (AST_XML_EXTENSIONS.has(ext)) {
    try {
      const parser = new XMLParser(XML_PARSER_OPTS);
      const parsed = parser.parse(text);
      const { masked, wasModified } = maskObjectValues(parsed);
      const builder = new XMLBuilder({
        ...XML_PARSER_OPTS,
        format: true,
        suppressEmptyNode: false,
      });
      return {
        cleanText: builder.build(masked),
        wasModified,
        route: 'ast:xml',
      };
    } catch (err) {
      console.warn('[SafeChat] XML parse failed, falling back to regex:', err);
      return { ...truncateAndSanitize(text), route: 'fallback:xml-parse-error' };
    }
  }

  // ── ENV / INI ─────────────────────────────────────────────────────────
  if (AST_ENV_EXTENSIONS.has(ext)) {
    try {
      const { cleanText, wasModified } = sanitizeEnvText(text);
      return { cleanText, wasModified, route: 'line:env' };
    } catch (err) {
      console.warn('[SafeChat] ENV parse failed, falling back to regex:', err);
      return { ...truncateAndSanitize(text), route: 'fallback:env-parse-error' };
    }
  }

  // ── Catch-all: unstructured text (.log, .txt, .md, .csv, terminal, etc.)
  return { ...truncateAndSanitize(text), route: 'regex:catch-all' };
}
