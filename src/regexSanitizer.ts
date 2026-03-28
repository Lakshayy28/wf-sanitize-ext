/**
 * regexSanitizer.ts — Mega-Dictionary & Dynamic Compiler
 * ═══════════════════════════════════════════════════════
 * Tier 3 engine for unstructured text (.txt, .log, terminal, user prompts).
 * Uses Capture Group 1 for secret values so surrounding keys are preserved.
 *
 * Also exports `DYNAMIC_AST_KEYS` consumed by the AST Guardian (astSanitizer).
 */

import type { CustomSecretDef } from './router';

// ────────────────────────────────────────────────────────────────────────────
// Dynamic AST Key list (shared with astSanitizer.ts)
// ────────────────────────────────────────────────────────────────────────────

export let DYNAMIC_AST_KEYS: string[] = [
  'secret', 'token', 'password', 'passwd', 'auth', 'credential',
  'cert', 'ssh', 'bearer', 'client_id', 'client_secret', 'private',
  'jwt', 'session', 'encryption_key', 'access_key', 'secret_key',
  'api_key', 'apikey', 'private_key',
];

/**
 * Tests whether a key name looks sensitive by matching against DYNAMIC_AST_KEYS.
 * Case-insensitive, matches partial key names (e.g. "db_password" matches "password").
 */
export function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return DYNAMIC_AST_KEYS.some(k => lower.includes(k));
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
  { name: 'IPv4 Address', regex: /\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g },
  { name: 'MAC Address', regex: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g },
  { name: 'Email Address', regex: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g },
  { name: 'Phone Number Fallback', regex: /\b(\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
];

// ────────────────────────────────────────────────────────────────────────────
// Dynamic Secret Hydrator
// ────────────────────────────────────────────────────────────────────────────

const CHARSET_MAP: Record<string, string> = {
  hex:          '[0-9a-fA-F]',
  alphanumeric: '[A-Za-z0-9]',
  base64:       '[A-Za-z0-9+/=]',
  all:          '[A-Za-z0-9_\\-./+!@#$%^&*()=]',
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
        const lower = k.toLowerCase();
        if (!DYNAMIC_AST_KEYS.includes(lower)) {
          DYNAMIC_AST_KEYS.push(lower);
        }
      }
    }

    // Build regex from prefix + charset + length
    const prefix = def.value_prefix ? escapeRegex(def.value_prefix) : '';
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

    const pattern = `${prefix}(${charClass}${quantifier})`;

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
      cleanText = cleanText.replace(rule.regex, (match, group1?: string) => {
        modified = true;
        if (group1) {
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
