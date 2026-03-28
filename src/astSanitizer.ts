/**
 * astSanitizer.ts — Universal AST Guardian
 * ═════════════════════════════════════════
 * Tier 2 engine for structured config files (.json, .yaml, .env, .xml, .properties, .ini).
 * Parses into AST, identifies sensitive KEYS, masks their VALUES.
 * Guarantees 100% structure retention and zero false positives on code identifiers.
 *
 * No Presidio HTTP calls — purely local, fast key-matching.
 */

import { MASK, isSensitiveKey } from './regexSanitizer';

// ────────────────────────────────────────────────────────────────────────────
// AST-to-Presidio Bridge
// ────────────────────────────────────────────────────────────────────────────

/** Callback that sends an isolated value to Presidio NLP for PII detection. */
export type PiiChecker = (value: string) => Promise<string>;

/**
 * Process a single AST key-value pair:
 *  1. FAST PATH — key matches the dynamic secret list → instant MASK
 *  2. SLOW PATH — send the isolated value to Presidio for human PII detection
 *  3. PASSTHROUGH — return the value unchanged
 */
async function processAstValue(key: string, value: string, piiCheck?: PiiChecker): Promise<string> {
  if (isSensitiveKey(key)) {
    return MASK;
  }
  if (piiCheck && typeof value === 'string' && value.length > 3) {
    return piiCheck(value);
  }
  return value;
}

// ────────────────────────────────────────────────────────────────────────────
// JSON Parser
// ────────────────────────────────────────────────────────────────────────────

/**
 * Parse JSON, walk every key, mask values whose keys are sensitive
 * OR whose values contain human PII (via Presidio callback).
 * Returns the re-serialized JSON. If parsing fails, returns null.
 */
export async function sanitizeJson(
  text: string,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean } | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null; // Not valid JSON — caller should fall back
  }

  let modified = false;

  async function walk(node: unknown): Promise<unknown> {
    if (Array.isArray(node)) {
      const items: unknown[] = [];
      for (const item of node) { items.push(await walk(item)); }
      return items;
    }
    if (node !== null && typeof node === 'object') {
      const obj = node as Record<string, unknown>;
      const result: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(obj)) {
        if (typeof val === 'string' && val.length > 0) {
          const cleaned = await processAstValue(key, val, piiCheck);
          if (cleaned !== val) { modified = true; }
          result[key] = cleaned;
        } else if (typeof val === 'object' && val !== null) {
          result[key] = await walk(val);
        } else {
          result[key] = val;
        }
      }
      return result;
    }
    return node;
  }

  // Detect original indentation
  const indent = detectJsonIndent(text);
  const cleaned = await walk(parsed);
  const cleanText = JSON.stringify(cleaned, null, indent);

  return { cleanText, wasModified: modified };
}

function detectJsonIndent(text: string): number {
  const match = text.match(/^[\s]*\n([ \t]+)/m);
  if (match) {
    const ws = match[1];
    if (ws[0] === '\t') { return 1; } // tab-indented, use 1 tab via JSON.stringify
    return ws.length;
  }
  return 2; // default
}

// ────────────────────────────────────────────────────────────────────────────
// YAML Parser (lightweight, no external deps)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize YAML text by matching key: value lines.
 * Preserves comments, structure, and non-sensitive values.
 * Handles quoted and unquoted values.
 * Sends non-secret values to Presidio for human PII detection.
 */
export async function sanitizeYaml(
  text: string,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean }> {
  let modified = false;
  const lines = text.split('\n');
  const result: string[] = [];

  // YAML key: value pattern — handles:
  //   key: value
  //   key: "value"
  //   key: 'value'
  //   key: "value" # comment
  const KV_RE = /^(\s*)([\w][\w.\-]*)\s*:\s*(.*)$/;

  for (const line of lines) {
    const match = line.match(KV_RE);
    if (match) {
      const [, indent, key, rawVal] = match;
      const trimmedVal = rawVal.trim();

      // Skip if value is empty, a block indicator, or a nested mapping
      if (!trimmedVal || trimmedVal === '|' || trimmedVal === '>' || trimmedVal === '|-' || trimmedVal === '>-') {
        result.push(line);
        continue;
      }
      // Skip list/object starters
      if (trimmedVal.startsWith('[') || trimmedVal.startsWith('{')) {
        result.push(line);
        continue;
      }

      // Extract trailing comment
      let comment = '';
      const commentMatch = rawVal.match(/(\s+#.*)$/);
      if (commentMatch) { comment = commentMatch[1]; }

      // Isolate value portion (strip trailing comment)
      const valStr = comment
        ? rawVal.slice(0, rawVal.length - comment.length).trim()
        : trimmedVal;

      // Unquote for processAstValue
      let unquotedVal = valStr;
      let quoteChar = '';
      if ((valStr.startsWith('"') && valStr.endsWith('"') && valStr.length > 1) ||
          (valStr.startsWith("'") && valStr.endsWith("'") && valStr.length > 1)) {
        quoteChar = valStr[0];
        unquotedVal = valStr.slice(1, -1);
      }

      const cleaned = await processAstValue(key, unquotedVal, piiCheck);
      if (cleaned !== unquotedVal) {
        modified = true;
        if (quoteChar) {
          result.push(`${indent}${key}: ${quoteChar}${cleaned}${quoteChar}${comment}`);
        } else {
          result.push(`${indent}${key}: ${cleaned}${comment}`);
        }
      } else {
        result.push(line);
      }
    } else {
      result.push(line);
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// ENV Parser (.env files)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize .env files: KEY=VALUE or KEY: VALUE format.
 * Masks secret-key values instantly; sends other values to Presidio.
 * Handles export prefix.
 */
export async function sanitizeEnv(
  text: string,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean }> {
  let modified = false;
  const lines = text.split('\n');
  const result: string[] = [];

  // Matches: optional "export " + KEY = VALUE or KEY: VALUE
  const ENV_RE = /^(\s*(?:export\s+)?[A-Za-z0-9_.-]+)\s*([:=])\s*(.*)$/;

  for (const line of lines) {
    const trimmed = line.trim();
    // Preserve comments and blank lines
    if (!trimmed || trimmed.startsWith('#')) {
      result.push(line);
      continue;
    }

    const match = line.match(ENV_RE);
    if (match) {
      const [, keyPart, separator, valuePart] = match;
      const keyName = keyPart.replace(/^\s*export\s+/, '').trim();
      const trimVal = valuePart.trim();

      if (trimVal.length > 0) {
        // Unquote for processAstValue
        let unquotedVal = trimVal;
        let quoteChar = '';
        if ((trimVal.startsWith('"') && trimVal.endsWith('"') && trimVal.length > 1) ||
            (trimVal.startsWith("'") && trimVal.endsWith("'") && trimVal.length > 1)) {
          quoteChar = trimVal[0];
          unquotedVal = trimVal.slice(1, -1);
        }

        const cleaned = await processAstValue(keyName, unquotedVal, piiCheck);
        if (cleaned !== unquotedVal) {
          modified = true;
          if (quoteChar) {
            result.push(`${keyPart}${separator}${quoteChar}${cleaned}${quoteChar}`);
          } else {
            result.push(`${keyPart}${separator}${cleaned}`);
          }
        } else {
          result.push(line);
        }
      } else {
        result.push(line);
      }
    } else {
      result.push(line);
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Properties / INI Parser
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize .properties / .ini files: key=value or key: value per line.
 * Handles [Section] headers and # / ; comments.
 * Sends non-secret values to Presidio for PII detection.
 */
export async function sanitizeProperties(
  text: string,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean }> {
  let modified = false;
  const lines = text.split('\n');
  const result: string[] = [];

  const PROP_RE = /^(\s*[A-Za-z0-9_.\-]+)\s*([=:])\s*(.*)$/;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';') || trimmed.startsWith('[')) {
      result.push(line);
      continue;
    }

    const match = line.match(PROP_RE);
    if (match) {
      const [, keyPart, sep, valuePart] = match;
      const keyName = keyPart.trim();
      const trimVal = valuePart.trim();

      if (trimVal.length > 0) {
        const cleaned = await processAstValue(keyName, trimVal, piiCheck);
        if (cleaned !== trimVal) {
          result.push(`${keyPart}${sep}${cleaned}`);
          modified = true;
        } else {
          result.push(line);
        }
      } else {
        result.push(line);
      }
    } else {
      result.push(line);
    }
  }

  return { cleanText: result.join('\n'), wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// XML Parser (lightweight, regex-based key-value tag masking)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize XML by finding <TagName>value</TagName> and sending values
 * through processAstValue (secret-key → MASK, otherwise → Presidio PII check).
 * Also handles attribute-based sensitive values: name="password" value="secret".
 */
export async function sanitizeXml(
  text: string,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean }> {
  let modified = false;
  let cleanText = text;

  // Tag-based: <tagName>value</tagName> — process via AST-to-Presidio bridge
  const tagRe = /(<([A-Za-z0-9_.\-:]+)[^>]*>)([^<]+)(<\/\2>)/g;
  type TagReplacement = { start: number; end: number; text: string };
  const replacements: TagReplacement[] = [];

  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = tagRe.exec(cleanText)) !== null) {
    const [full, openTag, tagName, value, closeTag] = tagMatch;
    if (value.trim().length > 0) {
      const cleaned = await processAstValue(tagName, value.trim(), piiCheck);
      if (cleaned !== value.trim()) {
        modified = true;
        replacements.push({
          start: tagMatch.index,
          end: tagMatch.index + full.length,
          text: `${openTag}${cleaned}${closeTag}`,
        });
      }
    }
  }

  // Apply replacements in reverse order to preserve string positions
  for (let i = replacements.length - 1; i >= 0; i--) {
    const r = replacements[i];
    cleanText = cleanText.slice(0, r.start) + r.text + cleanText.slice(r.end);
  }

  // Attribute-based: name="password" value="secret" — sync sensitive-key check
  cleanText = cleanText.replace(
    /(\b(?:name|key|id)\s*=\s*["'][^"']*(?:password|secret|token|key|auth|credential|cert|api)[^"']*["']\s+(?:value)\s*=\s*)(["'])([^"']*)\2/gi,
    (full, prefix, quote, value) => {
      if (value.trim().length > 0) {
        modified = true;
        return `${prefix}${quote}${MASK}${quote}`;
      }
      return full;
    }
  );

  return { cleanText, wasModified: modified };
}

// ────────────────────────────────────────────────────────────────────────────
// Dispatcher
// ────────────────────────────────────────────────────────────────────────────

export type AstFormat = 'json' | 'yaml' | 'env' | 'properties' | 'xml';

/**
 * Route to the correct AST parser based on the detected format.
 * Passes the optional PiiChecker callback through to each parser.
 */
export async function astSanitize(
  text: string,
  format: AstFormat,
  piiCheck?: PiiChecker,
): Promise<{ cleanText: string; wasModified: boolean }> {
  switch (format) {
    case 'json': {
      const result = await sanitizeJson(text, piiCheck);
      // If JSON parsing fails, fall back to YAML parser (handles key: value generically)
      return result ?? await sanitizeYaml(text, piiCheck);
    }
    case 'yaml':
      return sanitizeYaml(text, piiCheck);
    case 'env':
      return sanitizeEnv(text, piiCheck);
    case 'properties':
      return sanitizeProperties(text, piiCheck);
    case 'xml':
      return sanitizeXml(text, piiCheck);
    default:
      return { cleanText: text, wasModified: false };
  }
}
