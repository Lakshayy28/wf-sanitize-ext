/**
 * piiSanitizer.ts — Local PII Engine (Zero Network Calls)
 * ════════════════════════════════════════════════════════
 * Synchronous, regex-based PII detection for structured config values.
 * Replaces Presidio NLP for Tier 2 (AST) pipeline — key-heuristics + regex
 * catch 99%+ of PII in labelled config fields without any HTTP round-trip.
 *
 * Presidio NLP remains available for Tier 3 (unstructured text) where
 * key-heuristics don't exist and NER is genuinely needed.
 *
 * Extensible via safechat-rules.yaml `pii_patterns` section:
 *   - disable:         turn off specific built-in patterns by name
 *   - extra_keys:      extra key labels that force an instant MASK
 *   - extra_patterns:  custom organisation-specific regex patterns
 */

import { MASK, DYNAMIC_AST_KEYS } from './regexSanitizer';

// ────────────────────────────────────────────────────────────────────────────
// Config interface (exported so router.ts can add it to RulesConfig)
// ────────────────────────────────────────────────────────────────────────────

export interface PiiPatternsConfig {
  /**
   * Names of built-in PII patterns to disable. Case-insensitive.
   * Valid names: 'US SSN', 'Credit Card', 'IBAN', 'Email', 'Phone',
   *              'IPv4', 'Internal Hostname', 'MAC Address'
   */
  disable?: string[];
  /**
   * Extra key labels that trigger an immediate MASK (added to the
   * key-heuristic dictionary, identical to custom_secrets.ast_keys).
   * e.g. ['employee_id', 'badge_number', 'national_id']
   */
  extra_keys?: string[];
  /**
   * Custom organisation-specific regex patterns to scan AST values.
   * `pattern` must be a valid JavaScript regex string (no surrounding slashes).
   */
  extra_patterns?: Array<{ name: string; pattern: string }>;
}

// ────────────────────────────────────────────────────────────────────────────
// PII Key Dictionary — labels that indicate the VALUE contains personal data
// ────────────────────────────────────────────────────────────────────────────

export const PII_KEYS: Set<string> = new Set([
  // Identity
  'first_name', 'last_name', 'full_name', 'name', 'given_name', 'family_name',
  'middle_name', 'maiden_name', 'nickname', 'display_name',
  // Government IDs
  'ssn', 'social_security', 'social_security_number',
  'national_id', 'passport', 'passport_number',
  'driver_license', 'drivers_license', 'license_number',
  'tax_id', 'tin', 'ein',
  // Financial
  'credit_card', 'card_number', 'card_no', 'cc_number',
  'cvv', 'cvc', 'iban', 'bank_account', 'account_number', 'routing_number',
  // Contact
  'email', 'email_address', 'phone', 'phone_number', 'mobile', 'cell',
  'address', 'street_address', 'street', 'city', 'zipcode', 'zip_code', 'postal_code',
  // Dates
  'dob', 'date_of_birth', 'birth_date', 'birthday',
]);

// ────────────────────────────────────────────────────────────────────────────
// PII Value Patterns — built-in baselines (never modified)
// ────────────────────────────────────────────────────────────────────────────

const BUILTIN_PII_VALUE_PATTERNS: ReadonlyArray<{ name: string; regex: RegExp }> = [
  { name: 'US SSN',            regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'Credit Card',       regex: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b/g },
  { name: 'IBAN',              regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  { name: 'Email',             regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g },
  { name: 'Phone',             regex: /(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
  { name: 'IPv4',              regex: /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g },
  { name: 'Internal Hostname', regex: /\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.(?:internal|local|private)\b/gi },
  { name: 'MAC Address',       regex: /(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/g },
];

/** Names of all built-in patterns — exposed for YAML documentation autocomplete. */
export const BUILTIN_PII_PATTERN_NAMES: ReadonlyArray<string> =
  BUILTIN_PII_VALUE_PATTERNS.map(p => p.name);

// ────────────────────────────────────────────────────────────────────────────
// Runtime-active patterns (rebuilt by hydratePiiConfig on each config load)
// ────────────────────────────────────────────────────────────────────────────

let activePiiPatterns: Array<{ name: string; regex: RegExp }> =
  [...BUILTIN_PII_VALUE_PATTERNS];

// ────────────────────────────────────────────────────────────────────────────
// Hydration — called by sanitizer.ts::ensureHydrated() on each config load
// ────────────────────────────────────────────────────────────────────────────

/**
 * Rebuild the active PII pattern set from the YAML `pii_patterns` config.
 * Called every time the config hash changes — always rebuilds from scratch
 * so that a `disable` list change takes effect immediately.
 *
 * Side-effect: injects `extra_keys` into `DYNAMIC_AST_KEYS` so the
 * key-heuristic fast-path in processAstValue() masks them instantly.
 */
export function hydratePiiConfig(config?: PiiPatternsConfig): void {
  // 1. Start from builtins, filtered by the disable list
  const disabled = new Set((config?.disable ?? []).map(s => s.toLowerCase()));
  activePiiPatterns = BUILTIN_PII_VALUE_PATTERNS
    .filter(p => !disabled.has(p.name.toLowerCase()))
    .map(p => ({ name: p.name, regex: new RegExp(p.regex.source, p.regex.flags) }));

  // 2. Append custom organisation patterns
  for (const custom of config?.extra_patterns ?? []) {
    try {
      activePiiPatterns.push({ name: custom.name, regex: new RegExp(custom.pattern, 'gi') });
    } catch {
      // Invalid regex — skip silently to avoid crashing on bad config
    }
  }

  // 3. Inject extra_keys into the key-heuristic dictionary
  for (const key of config?.extra_keys ?? []) {
    DYNAMIC_AST_KEYS.add(key.toLowerCase());
    PII_KEYS.add(key.toLowerCase());
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * Synchronous PII value scanner.
 * Replaces recognised PII entities in an isolated AST value with MASK.
 * Only runs patterns that are currently active (respects `pii_patterns.disable`).
 */
export function localPiiScan(value: string): string {
  let result = value;
  for (const { regex } of activePiiPatterns) {
    regex.lastIndex = 0;
    result = result.replace(regex, MASK);
  }
  return result;
}
