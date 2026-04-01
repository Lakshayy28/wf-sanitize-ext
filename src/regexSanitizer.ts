/**
 * regexSanitizer.ts — Mega-Dictionary & Dynamic Compiler
 * ═══════════════════════════════════════════════════════
 * Tier 3 engine for unstructured text (.txt, .log, terminal, user prompts).
 * Uses Capture Group 1 for secret values so surrounding keys are preserved.
 *
 * Also exports `DYNAMIC_AST_KEYS` and `isSensitiveKey()` consumed by the
 * AST Guardian (astSanitizer). `isSensitiveKey` uses two-tier matching:
 *   Tier 1 — exact token match against DYNAMIC_AST_KEYS (no substring false-positives)
 *   Tier 2 — structural suffix match on the last token (catches infinite combinations
 *             like `myApp_refreshCred`, `svc_api_token_v2` without a word list)
 */

import type { CustomSecretDef } from './router';

// ────────────────────────────────────────────────────────────────────────────
// Dynamic AST Key set (shared with astSanitizer.ts, extended by hydration)
// ────────────────────────────────────────────────────────────────────────────

export const DYNAMIC_AST_KEYS: Set<string> = new Set([
  // Infrastructure secrets
  'secret', 'token', 'password', 'passwd', 'pass', 'pwd', 'passphrase', 'passcode',
  'auth', 'authorization', 'authentication', 'authenticate',
  'credential', 'credentials', 'cert', 'certificate', 'bearer', 'ssh',
  'jwt', 'session', 'private', 'key', 'apikey', 'accesskey', 'secretkey', 'signingkey',
  'client_id', 'client_secret', 'private_key', 'encryption_key', 'access_key', 'secret_key', 'api_key',
  // Infrastructure discovery (endpoints, hostnames, connection details)
  'dsn', 'fqdn', 'owner',
  // PII identifiers (catches SSN/CC/IBAN values under labeled keys)
  'ssn', 'social_security', 'credit_card', 'card_number', 'card_no',
  'cvv', 'cvc', 'iban', 'bank_account', 'account_number', 'routing_number',
  'national_id', 'passport', 'driver_license', 'drivers_license',
  'dob', 'date_of_birth', 'birth_date',
]);

/**
 * Structural suffixes — if the *last* meaningful token of a key is one of
 * these, the key is sensitive regardless of its prefix. Covers infinite
 * new combinations: `myApp_refreshToken`, `svc_api_key_v2`, `serviceAccountCred`.
 * Exported as a mutable Set so YAML config can extend it at runtime.
 */
export const SENSITIVE_SUFFIXES: Set<string> = new Set([
  'key', 'keys', 'token', 'tokens', 'secret', 'secrets',
  'pass', 'pwd', 'cred', 'creds', 'auth', 'cert', 'certs',
  'passphrase', 'passcode', 'credential', 'credentials',
  // Infrastructure endpoints & connection details
  'url', 'uri', 'host', 'hostname', 'endpoint', 'address', 'server', 'dsn', 'webhook',
  // PII contact fields
  'username', 'user', 'email', 'phone', 'contact', 'sid',
]);

/**
 * Split a key name into lowercase word tokens, handling snake_case, camelCase,
 * PascalCase, kebab-case, dots, and numeric separators.
 *   myApiKey     → ['my', 'api', 'key']
 *   db_password  → ['db', 'password']
 *   api-key-v2   → ['api', 'key', 'v2']
 *   authorName   → ['author', 'name']   ← does NOT match 'auth'
 *   ACLToken     → ['acl', 'token']
 */
function tokenizeKeyName(key: string): string[] {
  return key
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')  // ACLKey → ACL_Key
    .replace(/([a-z\d])([A-Z])/g, '$1_$2')        // apiKey → api_Key
    .toLowerCase()
    .split(/[\s_\-.:\/\\]+/)
    .filter(t => t.length > 0);
}

/**
 * Two-tier sensitive key detection.
 * Tier 1: any word-token in the key exactly matches DYNAMIC_AST_KEYS —
 *         eliminates substring false-positives ("author" no longer hits "auth").
 * Tier 2: the last non-version token is a structural suffix —
 *         catches any `<prefix>_<suffix>` combination without enumerating prefixes.
 */
export function isSensitiveKey(key: string): boolean {
  const tokens = tokenizeKeyName(key);
  if (tokens.some(t => DYNAMIC_AST_KEYS.has(t))) { return true; }
  const lastMeaningful = [...tokens].reverse().find(t => !/^\d+$/.test(t) && t.length > 1);
  return lastMeaningful !== undefined && SENSITIVE_SUFFIXES.has(lastMeaningful);
}

// ────────────────────────────────────────────────────────────────────────────
// Mask placeholder
// ────────────────────────────────────────────────────────────────────────────

export const MASK = '[MASKED_BY_SAFECHAT]';

// ────────────────────────────────────────────────────────────────────────────
// Secret pattern interface
// ────────────────────────────────────────────────────────────────────────────

export interface SecretPattern {
  name: string;
  regex: RegExp;
  /** When true, the regex uses 3 capture groups: protocol (G1), auth block (G2), @host (G3). */
  isUrlAuth?: boolean;
}

// ────────────────────────────────────────────────────────────────────────────
// HIGH_CONFIDENCE_SECRETS — The Mega-Dictionary
// ────────────────────────────────────────────────────────────────────────────

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

  // ── Generic URLs (Ultimate Fallbacks) ─────────────────────────────────────
  { name: 'URL Query Parameter Secret', regex: /(?:password|passwd|secret|token|api_?key|auth)=([^&\s"']+)/gi },
  { name: 'Credential URL', regex: /\b([a-zA-Z0-9+.-]+:\/\/)([^@\s]+)(@[a-zA-Z0-9.-]+(?::[\d]+)?(?:\/[^\s"']*)?)/gi, isUrlAuth: true },

  // ── Keyless Credential Files ──────────────────────────────────────────────
  { name: 'Netrc Password', regex: /(?:password|passwd)\s+([^\s]+)/gi },
  { name: 'Pgpass Password', regex: /^(?:[^:\r\n]+:){4}([^:\r\n]+)$/gm },

  // ── Tier 3 PII Fallback (for scripts/certs that bypass Presidio NLP) ──────
  // SSN: matches xxx-xx-xxxx (no Luhn needed — Presidio misses test/mock SSNs)
  { name: 'US SSN', regex: /\b(\d{3}-\d{2}-\d{4})\b/g },
  // Credit Card: 13-19 digit sequences, with optional dashes/spaces (no Luhn — catches test data)
  { name: 'Credit Card Number', regex: /\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7})\b/g },
  // IBAN: 2 uppercase letters + 2 check digits + 11-30 alphanumeric
  { name: 'IBAN Code', regex: /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g },
  // IPv4: whole-match replacement (no capture group to avoid partial masking)
  { name: 'IPv4 Address',     regex: /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g },
  // Internal hostnames: *.internal, *.local, *.private (org-internal FQDN patterns)
  { name: 'Internal Hostname', regex: /\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.(?:internal|local|private)\b/gi },
  { name: 'MAC Address',           regex: /(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/g },
  { name: 'Certificate Thumbprint', regex: /(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}/g },
  { name: 'Email Address',          regex: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
  // Phone: whole-match replacement (no partial capture group)
  { name: 'Phone Number Fallback', regex: /(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
];

// ────────────────────────────────────────────────────────────────────────────
// Dynamic Secret Hydrator
// ────────────────────────────────────────────────────────────────────────────

const CHARSET_MAP: Record<string, string> = {
  hex:          '[0-9a-fA-F]',
  alphanumeric: '[A-Za-z0-9]',
  base64:       '[A-Za-z0-9+/=]',
  all:          '[A-Za-z0-9_\\-.+/]',
};

/**
 * Hydrate custom_secrets from the YAML config into the runtime dictionaries.
 * - Pushes `ast_keys` into DYNAMIC_AST_KEYS.
 * - Compiles a safe regex from the definition and prepends it to HIGH_CONFIDENCE_SECRETS.
 */
export function hydrateCustomSecrets(customSecrets: CustomSecretDef[]): void {
  for (const def of customSecrets) {
    // Inject AST keys
    if (def.ast_keys) {
      for (const k of def.ast_keys) {
        DYNAMIC_AST_KEYS.add(k.toLowerCase());
      }
    }

    // Only compile a value-hunting regex when a prefix is defined.
    // Without a prefix the pattern degenerates to "match any long string"
    // which crosses key=value boundaries and masks keys.
    if (!def.value_prefix) { continue; }

    // Build regex from prefix + charset + length
    const prefix = escapeRegex(def.value_prefix);
    const charClass = CHARSET_MAP[def.value_charset || 'all'] || CHARSET_MAP.all;

    let quantifier: string;
    if (def.value_length) {
      const lenStr = String(def.value_length);
      if (lenStr.includes(',')) {
        const [min, max] = lenStr.split(',').map(s => s.trim());
        quantifier = `{${min},${max}}`;
      } else {
        quantifier = `{${lenStr}}`;
      }
    } else {
      quantifier = '{16,}';
    }

    const pattern = `\\b${prefix}(${charClass}${quantifier})\\b`;

    try {
      const compiledRegex = new RegExp(pattern, 'g');
      // Prepend so custom rules have priority over generic ones
      HIGH_CONFIDENCE_SECRETS.unshift({
        name: def.name,
        regex: compiledRegex,
      });
    } catch {
      console.warn(`[SafeChat] Failed to compile custom secret regex for "${def.name}": ${pattern}`);
    }
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ────────────────────────────────────────────────────────────────────────────
// Shannon Entropy Engine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Calculates the Shannon Entropy of a string.
 * Higher values = more cryptographic randomness.
 * Standard English text: ~2.5–3.5 | Base64 API keys: typically > 4.5
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) { return 0; }

  const charCounts = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of charCounts.values()) {
    const freq = count / len;
    entropy -= freq * Math.log2(freq);
  }

  return entropy;
}

/** Known high-entropy secret prefixes (service-specific). */
const SECRET_PREFIXES = [
  'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
  'sk-', 'pk_live_', 'pk_test_', 'sk_live_', 'sk_test_',
  'xoxb-', 'xoxp-', 'xoxs-', 'xoxa-',
  'eyJ', 'npm_', 'AKIA', 'ASIA',
  'glpat-', 'SG.', 'hvs.', 'hvb.', 'hvr.',
];

/** Heuristic: is this bare token likely a cryptographic secret? */
function looksLikeSecret(s: string): boolean {
  if (s.length < 16) { return false; }
  if (SECRET_PREFIXES.some(p => s.startsWith(p))) { return true; }
  const entropy = calculateShannonEntropy(s);
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
// Context-Anchored Entropy Scanner (replaces brittle Generic Secret Assignment)
// ────────────────────────────────────────────────────────────────────────────

/**
 * The Anchor Regex: loose match for any key=value, key: "value", key => "value"
 * where the key name contains a suspicious word. Captures the value in Group 1.
 *
 * This does NOT decide whether to mask — that's the Entropy Gate's job.
 */
const ENTROPY_ANCHOR_RE =
  /(?:key|secret|token|password|passwd|auth|credential|cert|ssh|api|bearer|client_id|client_secret|private_key|access_key|api_key)[A-Za-z0-9_]*\s*(?:[:=>])\s*["']?([A-Za-z0-9_.\-\/+!@#$%^&*()]{8,})["']?(?:<\/[A-Za-z0-9\-_]+>)?/gi;

/**
 * Hunts for unknown secrets by finding suspicious assignments and gating
 * on Shannon Entropy. If the value is mathematically random (entropy ≥ 3.8),
 * it is almost certainly a cryptographic secret — mask it.
 *
 * This replaces the old hardcoded "Generic Secret Assignment" regex,
 * making the system future-proof against new token formats.
 */
export function applyEntropyMasking(text: string): { cleanText: string; wasModified: boolean } {
  let modified = false;

  const cleanText = text.replace(ENTROPY_ANCHOR_RE, (match, secretValue: string) => {
    if (!secretValue) { return match; }
    // Skip if already masked
    if (match.includes(MASK)) { return match; }

    const entropy = calculateShannonEntropy(secretValue);

    // Entropy Gate: high randomness → cryptographic secret → mask
    if (entropy >= 3.8) {
      modified = true;
      return match.replace(secretValue, MASK);
    }

    // Low entropy (e.g., password="password123") — leave for Presidio NLP
    return match;
  });

  return { cleanText, wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Core regex sanitizer
// ────────────────────────────────────────────────────────────────────────────

/** Safe keyword prefixes to skip during Shannon entropy scanning. */
const SAFE_TOKEN_PREFIXES = [
  /^(?:\/|\.\/|[a-z]:[/\\]|https?:|file:)/i,
  /^(?:node_modules|package|function|return|import|export|require|undefined|interface|class|const|let|var)/i,
];

const BARE_TOKEN_RE = /(?:^|["'`=:\s])([A-Za-z0-9+/\-_]{20,}={0,3})(?:["'`\s;,}\])]|$)/gm;

/**
 * Apply every HIGH_CONFIDENCE_SECRETS regex + Shannon entropy to unstructured text.
 * When a pattern uses a capture group (group1), only that group is replaced
 * so surrounding key/prefix is preserved.
 */
export function regexSanitize(text: string): { cleanText: string; wasModified: boolean } {
  let modified = false;
  let cleanText = text;

  // Step 1: Dictionary regexes
  for (const rule of HIGH_CONFIDENCE_SECRETS) {
    rule.regex.lastIndex = 0;

    if (rule.isUrlAuth) {
      // Special handler for URLs: Rebuilds as protocol + MASK + @host
      cleanText = cleanText.replace(rule.regex, (_match, p1: string, _p2: string, p3: string) => {
        modified = true;
        return `${p1}${MASK}${p3}`;
      });
    } else {
      // Standard handler: Group 1 isolation (mask only the captured secret)
      // NOTE: when a regex has no capture groups, JS passes the match offset as the
      // second callback argument. The typeof guard prevents treating that number as a group.
      cleanText = cleanText.replace(rule.regex, (match, group1?: string | number) => {
        // Skip if already masked (prevents double-masking when regex safety net runs after AST)
        if (match.includes(MASK)) { return match; }
        modified = true;
        if (typeof group1 === 'string' && group1) {
          return match.replace(group1, MASK);
        }
        return MASK;
      });
    }
  }

  // Step 2: Context-Anchored Entropy Scanner (catches unknown secrets)
  const entropyResult = applyEntropyMasking(cleanText);
  cleanText = entropyResult.cleanText;
  if (entropyResult.wasModified) { modified = true; }

  // Step 3: Shannon entropy scan for bare high-entropy tokens
  const lines = cleanText.split('\n');
  for (let i = 0; i < lines.length; i++) {
    BARE_TOKEN_RE.lastIndex = 0;
    lines[i] = lines[i].replace(BARE_TOKEN_RE, (full, captured: string) => {
      if (full.includes(MASK)) { return full; }
      if (SAFE_TOKEN_PREFIXES.some(re => re.test(captured))) { return full; }
      if (looksLikeSecret(captured)) {
        modified = true;
        return full.replace(captured, MASK);
      }
      return full;
    });
  }
  cleanText = lines.join('\n');

  return { cleanText, wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Terminal-specific sanitizer
// ────────────────────────────────────────────────────────────────────────────

/** ANSI escape code stripper. */
const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]|\x1b\]\d*;[^\x07]*(?:\x07|\x1b\\)|\x1b[^\[\]][A-Za-z]/g;

export function stripAnsiCodes(text: string): string {
  return text.replace(ANSI_RE, '');
}

/**
 * Terminal-specific sanitizer: targeted regexes for CLI secrets
 * (curl headers, env vars, JSON fields, CLI flags, Bearer tokens, AWS keys).
 */
export function terminalSanitize(text: string): { cleanText: string; wasModified: boolean } {
  let wasModified = false;
  let result = text;

  // CLI flags: --password=value, --token value
  result = result.replace(
    /(--(?:password|passwd|token|secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[=\s]\s*)(\S+)/gi,
    (_, prefix) => { wasModified = true; return prefix + MASK; }
  );

  // curl -H "Authorization: Bearer <token>"
  result = result.replace(
    /(-H\s+["'](?:Authorization|X-Api-Key|X-Auth-Token)\s*:\s*(?:Bearer\s+)?)([^"']+)(["'])/gi,
    (_, prefix, _val, quote) => { wasModified = true; return prefix + MASK + quote; }
  );

  // JSON fields: "password": "value"
  result = result.replace(
    /(["'](?:password|passwd|secret|api_?key|token|access_?token|auth_?token|private_?key|client_?secret|jwt_?secret|session_?secret|signing_?key|encryption_?key|database_?url|connection_?string)["']\s*:\s*["'])([^"']+)(["'])/gi,
    (_, prefix, _val, quote) => { wasModified = true; return prefix + MASK + quote; }
  );

  // Env var assignments
  result = result.replace(
    /((?:^|\n)\s*(?:export\s+|SET\s+|ENV\s+)?(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|PRIVATE_?KEY|CLIENT_?SECRET|AWS_?SECRET_?ACCESS_?KEY|AWS_?SESSION_?TOKEN|DATABASE_?URL|DB_?PASSWORD|REDIS_?PASSWORD|MONGO_?URI)=)(.+)/gim,
    (_, prefix) => { wasModified = true; return prefix + MASK; }
  );

  // Bearer tokens (standalone)
  result = result.replace(
    /(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)/gi,
    (_, prefix) => { wasModified = true; return prefix + MASK; }
  );

  // AWS Access Key IDs
  result = result.replace(
    /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    () => { wasModified = true; return MASK; }
  );

  // Bare high-entropy tokens (standalone words 20+ chars)
  result = result.replace(
    /(?<=\s|^)([A-Za-z0-9\-._~+/]{20,})(?=\s|$)/gm,
    (match) => {
      if (looksLikeSecret(match)) { wasModified = true; return MASK; }
      return match;
    }
  );

  return { cleanText: result, wasModified };
}
