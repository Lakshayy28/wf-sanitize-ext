/**
 * sanitizer.ts — Smart Proxy: Polyglot AST Router + Regex DLP Engine
 * ════════════════════════════════════════════════════════════════════
 */

import * as yaml from 'yaml';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

export const MASK = '[MASKED_BY_SAFECHAT]';
const MAX_BUDGET_BYTES = 250_000; // 250 KB
const IS_DEV_MODE = true;

function logRedaction(patternName: string, matchedSecret: string): void {
  if (IS_DEV_MODE) {
    console.warn(`[SafeChat DEBUG] Redacted ${patternName}: "${matchedSecret}"`);
  } else {
    console.info(`[SafeChat AUDIT] Redacted ${patternName} (length: ${matchedSecret.length})`);
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Secret Pattern Dictionary (STRICT ENTERPRISE DICTIONARY)
// ────────────────────────────────────────────────────────────────────────────

export interface SecretPattern {
  name: string;
  regex: RegExp;
  isUrlAuth?: boolean;
}

export const HIGH_CONFIDENCE_SECRETS: SecretPattern[] = [
  { name: 'AWS Access Key',             regex: /\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}\b/g },
  { name: 'Stripe Key',                 regex: /\b([spr]k_(?:live|test)_[A-Za-z0-9]{24,99})\b/g },
  { name: 'Slack Token',                regex: /\b(xox[bpas]-[0-9A-Za-z\-]+)\b/g },
  { name: 'GitHub Token',               regex: /\b(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/g },
  { name: 'IPv4 Address',               regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g },
  { name: 'Email Address',              regex: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
  { name: 'Credit Card Number',         regex: /\b(?!(?:9007199254740991))(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b/g },
  { name: 'URI Password',               regex: /(?:\w+:\/\/)[^:\s@]+:([^:@\s]{6,})@/g },
  { name: 'Connection String Password', regex: /(?:password|pwd|secret)\s*=\s*([^;'"\s\\]{6,})/gi },
  { name: 'Pgpass Password', regex: /^(?:[^:\r\n]+:){4}([^:\r\n]+)$/gm },
];

// ────────────────────────────────────────────────────────────────────────────
// Configuration Management (`safechat.yml` dynamic routing)
// ────────────────────────────────────────────────────────────────────────────

let BYPASS_EXTENSIONS = new Set<string>();
let AST_JSON_EXTENSIONS = new Set<string>();
let AST_YAML_EXTENSIONS = new Set<string>();
let AST_XML_EXTENSIONS = new Set<string>();
let AST_ENV_EXTENSIONS = new Set<string>();
let DYNAMIC_PATTERNS: SecretPattern[] = [];

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

resetToDefaults();

export function updateConfig(config: any) {
  if (!config) {
    console.log('[SafeChat] Config absent or removed. Resetting to defaults.');
    resetToDefaults();
    return;
  }

  if (config.routing) {
    if (Array.isArray(config.routing.bypass)) { BYPASS_EXTENSIONS = new Set(config.routing.bypass); }
    if (Array.isArray(config.routing.ast_json)) { AST_JSON_EXTENSIONS = new Set(config.routing.ast_json); }
    if (Array.isArray(config.routing.ast_yaml)) { AST_YAML_EXTENSIONS = new Set(config.routing.ast_yaml); }
    if (Array.isArray(config.routing.ast_xml)) { AST_XML_EXTENSIONS = new Set(config.routing.ast_xml); }
    if (Array.isArray(config.routing.ast_env)) { AST_ENV_EXTENSIONS = new Set(config.routing.ast_env); }
  } else {
    resetToDefaults();
  }

  DYNAMIC_PATTERNS = [];
  if (Array.isArray(config.custom_patterns)) {
    for (const pat of config.custom_patterns) {
      if (pat.name && pat.regex) {
        try {
          let r = new RegExp(pat.regex, 'g');
          DYNAMIC_PATTERNS.push({ name: pat.name, regex: r });
        } catch (err) {
          console.warn(`[SafeChat] Failed to compile regex for custom pattern "${pat.name}":`, err);
        }
      }
    }
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Tier 1: Pure Regex Sanitizer
// ────────────────────────────────────────────────────────────────────────────

export function regexSanitize(text: string, redactions: string[] = []): { cleanText: string; wasModified: boolean } {
  let wasModified = false;
  let current = text;

  const allPatterns = [...HIGH_CONFIDENCE_SECRETS, ...DYNAMIC_PATTERNS];

  for (const pattern of allPatterns) {
    pattern.regex.lastIndex = 0;

    if (pattern.isUrlAuth) {
      const replaced = current.replace(pattern.regex, (_full, proto, _auth, host) => {
        wasModified = true;
        logRedaction(pattern.name, _auth);
        redactions.push(pattern.name);
        return `${proto}${MASK}${host}`;
      });
      if (replaced !== current) { current = replaced; }
    } else {
      const replaced = current.replace(pattern.regex, (full, captured) => {
        wasModified = true;
        const secretValue = captured !== undefined ? captured : full;
        logRedaction(pattern.name, secretValue);
        redactions.push(pattern.name);
        if (captured !== undefined) {
          return full.replace(captured, MASK);
        }
        return MASK;
      });
      if (replaced !== current) { current = replaced; }
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
      return MASK;
    }
    
    const entropy = calculateEntropy(match);
    if (entropy > 4.5) {
      wasModified = true;
      logRedaction('High Entropy Token', match);
      redactions.push('High Entropy Token');
      return MASK;
    }
    
    return match;
  });

  if (replacedWithEntropy !== current) { current = replacedWithEntropy; }

  return { cleanText: current, wasModified };
}

function hasSecretContext(text: string, matchIndex: number): boolean {
  const prefix = text.substring(Math.max(0, matchIndex - 40), matchIndex).toLowerCase();
  const anchorRegex = /secret|token|key|password|passwd|pwd|api|cred|auth|cert|signature/i;
  const assignmentRegex = /[:=]\s*["']?$/;
  return anchorRegex.test(prefix) || assignmentRegex.test(prefix);
}

export function calculateEntropy(str: string): number {
  if (!str) { return 0; }
  const len = str.length;
  const frequencies = new Map<string, number>();
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

export function maskObjectValues(
  obj: unknown,
  depth: number = 0,
  currentKey?: string,
  redactions: string[] = [],
): { masked: unknown; wasModified: boolean } {
  if (depth > MAX_DEPTH) {
    return { masked: obj, wasModified: false };
  }

  if (obj === null || obj === undefined) {
    return { masked: obj, wasModified: false };
  }

  if (typeof obj === 'string') {
    if (currentKey && SENSITIVE_KEY_HEURISTIC.test(currentKey)) {
      if (obj.length > 0 && obj !== MASK) {
        redactions.push('Key Heuristic Match');
        return { masked: MASK, wasModified: true };
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
      if (wasModified) { anyModified = true; }
      return masked;
    });
    return { masked: maskedArr, wasModified: anyModified };
  }

  let anyModified = false;
  const maskedObj: Record<string, unknown> = {};
  for (const [k, value] of Object.entries(obj as Record<string, unknown>)) {
    const { masked, wasModified } = maskObjectValues(value, depth + 1, k, redactions);
    maskedObj[k] = masked;
    if (wasModified) { anyModified = true; }
  }
  return { masked: maskedObj, wasModified: anyModified };
}

// ────────────────────────────────────────────────────────────────────────────
// Truncation + Regex Fallback
// ────────────────────────────────────────────────────────────────────────────

export function truncateAndSanitize(text: string, redactions: string[] = []): { cleanText: string; wasModified: boolean } {
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

function sanitizeEnvText(text: string, redactions: string[] = []): { cleanText: string; wasModified: boolean } {
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
      if (lm) { wasModified = true; }
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
      if (value.length > 0 && value !== MASK) {
        redactions.push('ENV Key Heuristic Match');
        wasModified = true;
        return quote ? `${key}=${quote}${MASK}${quote}` : `${key}=${MASK}`;
      }
      return quote ? `${key}=${quote}${value}${quote}` : `${key}=${value}`;
    }

    const { cleanText: maskedVal, wasModified: vm } = regexSanitize(value, redactions);
    if (vm) { wasModified = true; }

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

export function smartSanitize(
  text: string,
  fileExtension?: string,
  logFn: (msg: string) => void = () => { /* no-op */ },
): { cleanText: string; wasModified: boolean; route: string; redactions: string[] } {
  const redactions: string[] = [];

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
    } catch (err) {
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
    } catch (err) {
      return { ...truncateAndSanitize(text, redactions), route: 'fallback:yaml-parse-error', redactions };
    }
  }

  if (AST_XML_EXTENSIONS.has(ext)) {
    try {
      const parser = new XMLParser(XML_PARSER_OPTS);
      const parsed = parser.parse(text);
      const { masked, wasModified } = maskObjectValues(parsed, 0, undefined, redactions);
      const builder = new XMLBuilder({
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
    } catch (err) {
      return { ...truncateAndSanitize(text, redactions), route: 'fallback:xml-parse-error', redactions };
    }
  }

  if (AST_ENV_EXTENSIONS.has(ext)) {
    try {
      const { cleanText, wasModified } = sanitizeEnvText(text, redactions);
      return { cleanText, wasModified, route: 'line:env', redactions };
    } catch (err) {
      return { ...truncateAndSanitize(text, redactions), route: 'fallback:env-parse-error', redactions };
    }
  }

  return { ...truncateAndSanitize(text, redactions), route: 'regex:catch-all', redactions };
}